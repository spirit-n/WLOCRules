import argparse
from contextlib import closing
from pathlib import Path
import os
import shutil
import sqlite3
import subprocess
import tempfile


root = Path(__file__).resolve().parent
target = ('AppleIssued', 'apple.com', '^gs-loc$|^gs-loc-cn$')


def contents(path):
    with closing(sqlite3.connect(f'{path.as_uri()}?mode=ro', uri=True)) as db:
        assert db.execute('PRAGMA integrity_check').fetchall() == [('ok',)]
        return (
            db.execute('PRAGMA user_version').fetchone(),
            db.execute('SELECT * FROM admin ORDER BY key').fetchall(),
            db.execute('SELECT * FROM rules ORDER BY policyName,domainSuffix,labelRegex').fetchall(),
        )


def create_sample(path):
    with closing(sqlite3.connect(path)) as db, db:
        db.executescript('''
            PRAGMA user_version = 3;
            CREATE TABLE admin (key TEXT PRIMARY KEY, ival INTEGER, value BLOB);
            INSERT INTO admin VALUES ('version', 131, NULL);
            CREATE TABLE rules (
                policyName TEXT, domainSuffix TEXT, labelRegex TEXT,
                policies BLOB, transparentConnection INTEGER,
                UNIQUE (policyName, domainSuffix, labelRegex)
            );
        ''')
        db.executemany('INSERT INTO rules VALUES (?, ?, ?, ?, ?)', [
            (*target, bytes(1580), 0),
            ('AppleIssued', 'apple.com', '^other$', b'unrelated', 0),
            ('AppleIssued', 'example.com', target[2], b'unrelated', 0),
            ('OtherPolicy', 'apple.com', target[2], b'unrelated', 1),
        ])


parser = argparse.ArgumentParser(description='Test the rules helper on disposable SQLite files.')
parser.add_argument('--sample', type=Path, help='Optional local copy of an original v131 database')
args = parser.parse_args()
if os.geteuid() != 0:
    parser.error('Run with sudo to test the helper’s root-only entry point.')

with tempfile.TemporaryDirectory(prefix='wloc-helper-test-') as directory:
    temp = Path(directory)
    sample = args.sample.resolve(strict=True) if args.sample else temp / 'sample.sqlite3'
    if args.sample is None:
        create_sample(sample)
    live = temp / 'live.sqlite3'
    backup = temp / 'backup.sqlite3'
    binary = temp / 'tester'
    sdk = root / os.environ.get('WLOC_SDK', '../ios-sdks/iPhoneOS15.6.sdk')
    header = sdk / 'usr/include/sqlite3.h'
    if header.is_file():
        shutil.copyfile(header, temp / 'sqlite3.h')
    harness = temp / 'harness.c'
    harness.write_text(
        '#include "rules.h"\n#include "localization.h"\n'
        'int main(int argc, char **argv) {\n'
        '    if (argc != 2 && argc != 3) return 64;\n'
        '    wloc_set_language(argc == 3 ? argv[2] : "en");\n'
        '    return run_rules_command(argv[1]);\n}\n'
    )
    subprocess.run(['gcc','-std=gnu11','-Wall','-Wextra','-Werror','-I',str(root),'-I',str(temp),
                    f'-DWLOC_LIVE_DB="{live}"', f'-DWLOC_BACKUP_DB="{backup}"',
                    str(harness), str(root / 'rules.c'), str(root / 'localization.c'),
                    '-l:libsqlite3.so.0', '-o', str(binary)], check=True)
    baseline = contents(sample)
    expected = baseline[:2] + ([row for row in baseline[2] if row[:3] != target],)
    assert len(baseline[2]) - len(expected[2]) == 1, 'Sample must contain exactly one target rule'

    def run(command, want=0, language=None, **kwargs):
        arguments = [binary, command]
        if language is not None:
            arguments.append(language)
        result = subprocess.run(arguments, text=True, capture_output=True, timeout=12, **kwargs)
        assert result.returncode == want, (command, result.returncode, result.stdout, result.stderr)
        return result.stdout + result.stderr

    def reset():
        if backup.exists() or backup.is_symlink():
            backup.unlink()
        shutil.copyfile(sample, live)
        os.chmod(live, 0o600)

    reset()
    attrs = live.stat()
    assert 'present' in run('check') and not backup.exists()
    run('apply')
    assert contents(live) == expected and contents(backup) == baseline
    assert live.stat().st_mode == attrs.st_mode and live.stat().st_ino == attrs.st_ino
    assert 'absent' in run('check')
    assert 'already absent' in run('apply')
    run('restore')
    assert contents(live) == baseline
    assert 'already present' in run('restore')
    run('apply')
    run('restore')
    assert contents(live) == baseline
    print('PASS read-only check, backup, apply, restore, repeat, mode and inode')

    reset()
    for language in ('en', 'fr', 'zh-Hant', 'unknown'):
        assert 'Target rule: present' in run('check', language=language)
    chinese_log = run('check', language='zh-Hans')
    assert '目标规则：存在' in chinese_log and '内容版本=131' in chinese_log
    assert '文件或目录不存在' in chinese_log and 'Target rule:' not in chinese_log
    assert '修改完成' in run('apply', language='zh-Hans')
    assert contents(live) == expected and contents(backup) == baseline
    assert '已经移除' in run('apply', language='zh-Hans')
    assert '目标规则：已移除' in run('check', language='zh-Hans')
    assert '恢复完成' in run('restore', language='zh-Hans')
    assert contents(live) == baseline
    print('PASS Simplified Chinese logs and English fallback, apply and restore')

    reset()
    with closing(sqlite3.connect(live)) as db, db:
        db.execute("UPDATE admin SET ival=132 WHERE key='version'")
    changed = contents(live)
    assert 'Expected content 131' in run('apply', 1)
    assert '要求内容版本为 131' in run('apply', 1, language='zh-Hans')
    assert contents(live) == changed and not backup.exists()
    print('PASS unexpected content version refused')

    reset()
    with closing(sqlite3.connect(live)) as db, db:
        db.execute('BEGIN IMMEDIATE')
        assert 'locked' in run('apply', 1)
        assert '数据库正忙' in run('apply', 1, language='zh-Hans')
    assert contents(live) == baseline and not backup.exists()
    print('PASS busy database left intact')

    reset()
    backup.symlink_to(sample)
    assert 'private backup' in run('apply', 1)
    assert '权限为 0600' in run('apply', 1, language='zh-Hans')
    assert contents(live) == baseline
    print('PASS symlink backup refused')

    reset()
    keeper = sqlite3.connect(live)
    keeper.execute('PRAGMA journal_mode=WAL')
    keeper.execute('PRAGMA wal_autocheckpoint=0')
    keeper.execute("INSERT INTO admin VALUES('testWal', 42, NULL)")
    keeper.commit()
    wal_baseline = contents(live)
    wal_expected = wal_baseline[:2] + (expected[2],)
    run('apply')
    assert contents(live) == wal_expected and contents(backup) == wal_baseline
    run('restore')
    assert contents(live) == wal_baseline
    keeper.close()
    print('PASS WAL snapshot, transaction, and restore')
