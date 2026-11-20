#include "rules.h"
#include "localization.h"
#include <errno.h>
#include <fcntl.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef WLOC_LIVE_DB
#define WLOC_LIVE_DB "/private/var/protected/trustd/pinningrules.sqlite3"
#endif
#ifndef WLOC_BACKUP_DB
#define WLOC_BACKUP_DB "/private/var/root/wloc-pinning-v131.sqlite3"
#endif

#define TARGET_POLICY "'AppleIssued'"
#define TARGET_SUFFIX "'apple.com'"
#define TARGET_LABELS "'^gs-loc$|^gs-loc-cn$'"
#define MATCH "policyName=" TARGET_POLICY " AND domainSuffix=" TARGET_SUFFIX \
              " AND labelRegex=" TARGET_LABELS

enum { TARGET_POLICY_BYTES = 1580 };

static void sqlite_error(sqlite3 *db, const char *operation, const char *message) {
    fprintf(stderr, "%s: %s (SQLite %d, errno %d)\n", operation,
            wloc_sqlite_error(sqlite3_errcode(db), message ? message : sqlite3_errmsg(db)),
            sqlite3_extended_errcode(db), sqlite3_system_errno(db));
}

static int execute(sqlite3 *db, const char *sql) {
    char *error = NULL;
    int result = sqlite3_exec(db, sql, NULL, NULL, &error);
    if (result != SQLITE_OK) {
        const char *operation = strncmp(sql, "DELETE", 6) == 0
            ? wloc_text("Delete target rule", "删除目标规则") : wloc_text(sql, "执行 SQL");
        sqlite_error(db, operation, error);
    }
    sqlite3_free(error);
    return result == SQLITE_OK;
}

static void show_file(const char *label, const char *path) {
    struct stat attrs;
    if (lstat(path, &attrs) != 0) {
        int error = errno;
        printf("%s: %s (%d)\n", label, wloc_system_error(error), error);
        return;
    }
    printf(wloc_text("%s: uid=%u gid=%u mode=%04o", "%s：用户 ID=%u，组 ID=%u，权限=%04o"), label, (unsigned)attrs.st_uid,
           (unsigned)attrs.st_gid, (unsigned)(attrs.st_mode & 07777));
#ifdef __APPLE__
    printf(wloc_text(" flags=0x%x", "，文件标志=0x%x"), (unsigned)attrs.st_flags);
#endif
    puts("");
}

static int show_live_access(void) {
    char directory[] = WLOC_LIVE_DB;
    *strrchr(directory, '/') = '\0';
    show_file(wloc_text("trustd directory", "trustd 目录"), directory);
    show_file(wloc_text("Live DB", "当前数据库"), WLOC_LIVE_DB);
    show_file(wloc_text("WAL", "WAL 日志"), WLOC_LIVE_DB "-wal");
    show_file(wloc_text("SHM", "共享内存文件"), WLOC_LIVE_DB "-shm");
    show_file(wloc_text("Journal", "回滚日志"), WLOC_LIVE_DB "-journal");
    int fd = open(WLOC_LIVE_DB, O_RDWR | O_NOFOLLOW);
    if (fd == -1) {
        int error = errno;
        printf(wloc_text("Live DB open(O_RDWR): %s (%d)\n", "读写打开当前数据库：%s（%d）\n"),
               wloc_system_error(error), error);
    } else {
        close(fd);
        puts(wloc_text("Live DB open(O_RDWR): OK", "读写打开当前数据库：成功"));
    }
    if (access(directory, W_OK | X_OK) != 0) {
        int error = errno;
        printf(wloc_text("Directory access(W_OK|X_OK): %s (%d)\n", "目录写入与访问权限：%s（%d）\n"),
               wloc_system_error(error), error);
    } else {
        puts(wloc_text("Directory access(W_OK|X_OK): OK (file creation not tested)",
                       "目录写入与访问权限：允许（未测试创建文件）"));
    }
    return fd != -1;
}

static void show_journal_mode(sqlite3 *db) {
    sqlite3_stmt *statement = NULL;
    if (sqlite3_prepare_v2(db, "PRAGMA journal_mode", -1, &statement, NULL) == SQLITE_OK &&
        sqlite3_step(statement) == SQLITE_ROW && sqlite3_column_text(statement, 0)) {
        printf(wloc_text("Live journal mode: %s\n", "当前数据库日志模式：%s\n"),
               (const char *)sqlite3_column_text(statement, 0));
    } else {
        sqlite_error(db, wloc_text("Read journal mode", "读取日志模式"), NULL);
    }
    sqlite3_finalize(statement);
}

static int scalar(sqlite3 *db, const char *sql, int *value) {
    sqlite3_stmt *stmt = NULL;
    int ok = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK &&
             sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_type(stmt, 0) == SQLITE_INTEGER;
    if (ok) *value = sqlite3_column_int(stmt, 0);
    if (!ok) sqlite_error(db, wloc_text("Database metadata", "读取数据库元数据"), NULL);
    sqlite3_finalize(stmt);
    return ok;
}

static int inspect(sqlite3 *db, int *count) {
    int version = -1, schema = -1, triggers = -1;
    if (!scalar(db, "SELECT ival FROM admin WHERE key='version'", &version) ||
        !scalar(db, "PRAGMA user_version", &schema) ||
        !scalar(db, "SELECT count(*) FROM sqlite_master WHERE type='trigger'", &triggers)) return 0;
    printf(wloc_text("%s content: %d; schema: %d\n", "%s：内容版本=%d，结构版本=%d\n"),
           strcmp(sqlite3_db_filename(db, "main"), WLOC_BACKUP_DB) == 0
               ? wloc_text("Backup DB", "备份数据库") : wloc_text("Live DB", "当前数据库"),
           version, schema);
    if (version != 131 || schema != 3 || triggers != 0) {
        fprintf(stderr, "%s\n", wloc_text("Expected content 131, schema 3 and no triggers.",
                "要求内容版本为 131、结构版本为 3，且不存在触发器。"));
        return 0;
    }
    sqlite3_stmt *check = NULL;
    int ok = sqlite3_prepare_v2(db, "PRAGMA quick_check(1)", -1, &check, NULL) == SQLITE_OK &&
             sqlite3_step(check) == SQLITE_ROW && sqlite3_column_text(check, 0) &&
             strcmp((const char *)sqlite3_column_text(check, 0), "ok") == 0;
    sqlite3_finalize(check);
    if (!ok) {
        fprintf(stderr, "%s\n", wloc_text("Database integrity check failed.", "数据库完整性检查失败。"));
        return 0;
    }
    if (!scalar(db, "SELECT count(*) FROM rules WHERE " MATCH, count)) return 0;
    if (*count > 1) {
        fprintf(stderr, wloc_text("Expected at most one target rule; found %d.\n",
                "目标规则应最多只有一条，实际找到 %d 条。\n"), *count);
        return 0;
    }
    return 1;
}

static sqlite3 *open_db(const char *path, int flags) {
    struct stat attrs;
    if (lstat(path, &attrs) != 0) {
        fprintf(stderr, wloc_text("Cannot access %s: %s\n", "无法访问 %s：%s\n"), path, wloc_system_error(errno));
        return NULL;
    }
    if (!S_ISREG(attrs.st_mode)) {
        fprintf(stderr, wloc_text("Expected a regular database file: %s\n", "数据库必须是普通文件：%s\n"), path);
        return NULL;
    }
#ifdef SQLITE_OPEN_NOFOLLOW
    flags |= SQLITE_OPEN_NOFOLLOW;
#endif
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(path, &db, flags, NULL) != SQLITE_OK) {
        sqlite_error(db, path, NULL);
        sqlite3_close(db);
        return NULL;
    }
    sqlite3_busy_timeout(db, 2000);
    if (!execute(db, "PRAGMA trusted_schema=OFF")) {
        sqlite3_close(db);
        return NULL;
    }
    return db;
}

static sqlite3_stmt *read_rule(sqlite3 *db) {
    sqlite3_stmt *row = NULL;
    if (sqlite3_prepare_v2(db, "SELECT policies,transparentConnection FROM rules WHERE " MATCH,
                           -1, &row, NULL) == SQLITE_OK && sqlite3_step(row) == SQLITE_ROW &&
        sqlite3_column_type(row, 0) == SQLITE_BLOB &&
        sqlite3_column_bytes(row, 0) == TARGET_POLICY_BYTES &&
        sqlite3_column_type(row, 1) == SQLITE_INTEGER && sqlite3_column_int(row, 1) == 0) return row;
    fprintf(stderr, "%s\n", wloc_text("The target rule differs from the expected v131 rule.",
            "目标规则与预期的 v131 规则不一致。"));
    sqlite3_finalize(row);
    return NULL;
}

static int create_backup(void) {
    char path[] = WLOC_BACKUP_DB ".tmp.XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        fprintf(stderr, wloc_text("Cannot create backup: %s\n", "无法创建备份：%s\n"), wloc_system_error(errno));
        return 0;
    }
    sqlite3 *src = open_db(WLOC_LIVE_DB, SQLITE_OPEN_READONLY);
    sqlite3 *dst = src ? open_db(path, SQLITE_OPEN_READWRITE) : NULL;
    sqlite3_backup *backup = dst ? sqlite3_backup_init(dst, "main", src, "main") : NULL;
    int ok = 0;
    if (backup) {
        int step = sqlite3_backup_step(backup, -1);
        int finish = sqlite3_backup_finish(backup);
        ok = step == SQLITE_DONE && finish == SQLITE_OK;
    }
    if (!ok && dst) sqlite_error(dst, wloc_text("SQLite backup", "备份数据库"), NULL);
    if (dst) sqlite3_close(dst);
    if (src) sqlite3_close(src);
    if (ok && (fsync(fd) != 0 || link(path, WLOC_BACKUP_DB) != 0)) {
        fprintf(stderr, wloc_text("Cannot save backup: %s\n", "无法保存备份：%s\n"), wloc_system_error(errno));
        ok = 0;
    }
    close(fd);
    unlink(path);
    return ok;
}

static sqlite3 *checked_backup(void) {
    struct stat attrs;
    if (lstat(WLOC_BACKUP_DB, &attrs) != 0 || !S_ISREG(attrs.st_mode) ||
        attrs.st_uid != geteuid() || (attrs.st_mode & 0777) != 0600) {
        fprintf(stderr, "%s\n", wloc_text("A private backup owned by the helper is required.",
                "需要由辅助进程拥有、权限为 0600 的普通备份文件。"));
        return NULL;
    }
    sqlite3 *backup = open_db(WLOC_BACKUP_DB, SQLITE_OPEN_READONLY);
    int count = 0;
    if (backup && (!inspect(backup, &count) || count != 1)) {
        sqlite3_close(backup);
        return NULL;
    }
    return backup;
}

static int apply(sqlite3 *db) {
    sqlite3_stmt *current = read_rule(db);
    if (!current) return 0;
    struct stat attrs;
    int found = lstat(WLOC_BACKUP_DB, &attrs);
    if (found != 0 && errno == ENOENT && !create_backup()) {
        sqlite3_finalize(current);
        return 0;
    }
    sqlite3 *backup = checked_backup();
    sqlite3_stmt *saved = backup ? read_rule(backup) : NULL;
    int equal = saved && memcmp(sqlite3_column_blob(current, 0), sqlite3_column_blob(saved, 0),
                               TARGET_POLICY_BYTES) == 0;
    sqlite3_finalize(current);
    sqlite3_finalize(saved);
    if (backup) sqlite3_close(backup);
    if (!equal) {
        fprintf(stderr, "%s\n", wloc_text("The existing backup does not match the target rule.",
                "现有备份与当前目标规则不匹配。"));
        return 0;
    }
    return execute(db, "DELETE FROM rules WHERE " MATCH) && sqlite3_changes(db) == 1;
}

static int restore(sqlite3 *db) {
    sqlite3 *backup = checked_backup();
    if (!backup) return 0;
    sqlite3_stmt *row = read_rule(backup);
    sqlite3_stmt *insert = NULL;
    int ok = row && sqlite3_prepare_v2(db,
        "INSERT INTO rules(policyName,domainSuffix,labelRegex,policies,transparentConnection) "
        "VALUES(" TARGET_POLICY "," TARGET_SUFFIX "," TARGET_LABELS ",?,0)", -1, &insert, NULL) == SQLITE_OK &&
        sqlite3_bind_blob(insert, 1, sqlite3_column_blob(row, 0), TARGET_POLICY_BYTES,
                          SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_step(insert) == SQLITE_DONE && sqlite3_changes(db) == 1;
    if (!ok) sqlite_error(db, wloc_text("Restore target rule", "恢复目标规则"), NULL);
    sqlite3_finalize(insert);
    sqlite3_finalize(row);
    sqlite3_close(backup);
    return ok;
}

int run_rules_command(const char *command) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int check = strcmp(command, "check") == 0;
    int applying = strcmp(command, "apply") == 0;
    if (!check && !applying && strcmp(command, "restore") != 0) return 64;
    printf(wloc_text("Helper effective UID: %u; real UID: %u; effective GID: %u\n",
                    "辅助进程有效用户 ID=%u，实际用户 ID=%u，有效组 ID=%u\n"),
           (unsigned)geteuid(), (unsigned)getuid(), (unsigned)getegid());
    if (geteuid() != 0) {
        fprintf(stderr, "%s\n", wloc_text("The helper must run as root.", "辅助进程必须以 root 身份运行。"));
        return 1;
    }
    int live_writable = show_live_access();
    if (!check && !live_writable) {
        fprintf(stderr, "%s\n", wloc_text("The OS refused a writable file descriptor. No write transaction was started.",
                "系统拒绝读写打开数据库，未开始写入事务。"));
        return 1;
    }
    sqlite3 *db = open_db(WLOC_LIVE_DB, check ? SQLITE_OPEN_READONLY : SQLITE_OPEN_READWRITE);
    if (!db) return 1;
    show_journal_mode(db);
    if (!check) printf(wloc_text("SQLite write connection readonly: %d\n", "SQLite 写入连接是否为只读：%d\n"),
                       sqlite3_db_readonly(db, "main"));
    int count = 0;
    int ok = (check || execute(db, "BEGIN IMMEDIATE")) && inspect(db, &count);
    if (ok && check) {
        printf(wloc_text("Target rule: %s\n", "目标规则：%s\n"),
               count ? wloc_text("present", "存在") : wloc_text("absent", "已移除"));
    } else if (ok && count == applying) {
        ok = applying ? apply(db) : restore(db);
        int after = -1;
        ok = ok && scalar(db, "SELECT count(*) FROM rules WHERE " MATCH, &after) && after == !applying;
        ok = ok && execute(db, "COMMIT");
        if (ok) printf(wloc_text("%s. Restart iPhone to validate with trustd.\n", "%s。请重启 iPhone 后验证实际效果。\n"),
                       applying ? wloc_text("Applied", "修改完成") : wloc_text("Restored", "恢复完成"));
    } else if (ok) {
        printf(wloc_text("Target rule is already %s.\n", "目标规则%s。\n"),
               applying ? wloc_text("absent", "已经移除") : wloc_text("present", "已经存在"));
    }
    if (!sqlite3_get_autocommit(db)) execute(db, "ROLLBACK");
    sqlite3_close(db);
    return ok ? 0 : 1;
}
