#include "rules.h"
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
            message ? message : sqlite3_errmsg(db), sqlite3_extended_errcode(db), sqlite3_system_errno(db));
}

static int execute(sqlite3 *db, const char *sql) {
    char *error = NULL;
    int result = sqlite3_exec(db, sql, NULL, NULL, &error);
    if (result != SQLITE_OK) {
        const char *operation = strncmp(sql, "DELETE", 6) == 0 ? "Delete target rule" : sql;
        sqlite_error(db, operation, error);
    }
    sqlite3_free(error);
    return result == SQLITE_OK;
}

static void show_file(const char *label, const char *path) {
    struct stat attrs;
    if (lstat(path, &attrs) != 0) {
        int error = errno;
        printf("%s: %s (%d)\n", label, strerror(error), error);
        return;
    }
    printf("%s: uid=%u gid=%u mode=%04o", label, (unsigned)attrs.st_uid,
           (unsigned)attrs.st_gid, (unsigned)(attrs.st_mode & 07777));
#ifdef __APPLE__
    printf(" flags=0x%x", (unsigned)attrs.st_flags);
#endif
    puts("");
}

static int show_live_access(void) {
    char directory[] = WLOC_LIVE_DB;
    *strrchr(directory, '/') = '\0';
    show_file("trustd directory", directory);
    show_file("Live DB", WLOC_LIVE_DB);
    show_file("WAL", WLOC_LIVE_DB "-wal");
    show_file("SHM", WLOC_LIVE_DB "-shm");
    show_file("Journal", WLOC_LIVE_DB "-journal");
    int fd = open(WLOC_LIVE_DB, O_RDWR | O_NOFOLLOW);
    if (fd == -1) {
        int error = errno;
        printf("Live DB open(O_RDWR): %s (%d)\n", strerror(error), error);
    } else {
        close(fd);
        puts("Live DB open(O_RDWR): OK");
    }
    if (access(directory, W_OK | X_OK) != 0) {
        int error = errno;
        printf("Directory access(W_OK|X_OK): %s (%d)\n", strerror(error), error);
    } else {
        puts("Directory access(W_OK|X_OK): OK (file creation not tested)");
    }
    return fd != -1;
}

static void show_journal_mode(sqlite3 *db) {
    sqlite3_stmt *statement = NULL;
    if (sqlite3_prepare_v2(db, "PRAGMA journal_mode", -1, &statement, NULL) == SQLITE_OK &&
        sqlite3_step(statement) == SQLITE_ROW && sqlite3_column_text(statement, 0)) {
        printf("Live journal mode: %s\n", (const char *)sqlite3_column_text(statement, 0));
    } else {
        sqlite_error(db, "Read journal mode", NULL);
    }
    sqlite3_finalize(statement);
}

static int scalar(sqlite3 *db, const char *sql, int *value) {
    sqlite3_stmt *stmt = NULL;
    int ok = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK &&
             sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_type(stmt, 0) == SQLITE_INTEGER;
    if (ok) *value = sqlite3_column_int(stmt, 0);
    if (!ok) fprintf(stderr, "Database metadata: %s\n", sqlite3_errmsg(db));
    sqlite3_finalize(stmt);
    return ok;
}

static int inspect(sqlite3 *db, int *count) {
    int version = -1, schema = -1, triggers = -1;
    if (!scalar(db, "SELECT ival FROM admin WHERE key='version'", &version) ||
        !scalar(db, "PRAGMA user_version", &schema) ||
        !scalar(db, "SELECT count(*) FROM sqlite_master WHERE type='trigger'", &triggers)) return 0;
    printf("%s content: %d; schema: %d\n",
           strcmp(sqlite3_db_filename(db, "main"), WLOC_BACKUP_DB) == 0 ? "Backup DB" : "Live DB",
           version, schema);
    if (version != 131 || schema != 3 || triggers != 0) {
        fprintf(stderr, "Expected content 131, schema 3 and no triggers.\n");
        return 0;
    }
    sqlite3_stmt *check = NULL;
    int ok = sqlite3_prepare_v2(db, "PRAGMA quick_check(1)", -1, &check, NULL) == SQLITE_OK &&
             sqlite3_step(check) == SQLITE_ROW && sqlite3_column_text(check, 0) &&
             strcmp((const char *)sqlite3_column_text(check, 0), "ok") == 0;
    sqlite3_finalize(check);
    if (!ok) {
        fprintf(stderr, "Database integrity check failed.\n");
        return 0;
    }
    if (!scalar(db, "SELECT count(*) FROM rules WHERE " MATCH, count)) return 0;
    if (*count > 1) {
        fprintf(stderr, "Expected at most one target rule; found %d.\n", *count);
        return 0;
    }
    return 1;
}

static sqlite3 *open_db(const char *path, int flags) {
    struct stat attrs;
    if (lstat(path, &attrs) != 0) {
        fprintf(stderr, "Cannot access %s: %s\n", path, strerror(errno));
        return NULL;
    }
    if (!S_ISREG(attrs.st_mode)) {
        fprintf(stderr, "Expected a regular database file: %s\n", path);
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
    fprintf(stderr, "The target rule differs from the expected v131 rule.\n");
    sqlite3_finalize(row);
    return NULL;
}

static int create_backup(void) {
    char path[] = WLOC_BACKUP_DB ".tmp.XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        fprintf(stderr, "Cannot create backup: %s\n", strerror(errno));
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
    if (!ok && dst) fprintf(stderr, "SQLite backup: %s\n", sqlite3_errmsg(dst));
    if (dst) sqlite3_close(dst);
    if (src) sqlite3_close(src);
    if (ok && (fsync(fd) != 0 || link(path, WLOC_BACKUP_DB) != 0)) {
        fprintf(stderr, "Cannot save backup: %s\n", strerror(errno));
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
        fprintf(stderr, "A private backup owned by the helper is required.\n");
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
        fprintf(stderr, "The existing backup does not match the target rule.\n");
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
    if (!ok) sqlite_error(db, "Restore target rule", NULL);
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
    printf("Helper effective UID: %u; real UID: %u; effective GID: %u\n",
           (unsigned)geteuid(), (unsigned)getuid(), (unsigned)getegid());
    if (geteuid() != 0) {
        fprintf(stderr, "The helper must run as root.\n");
        return 1;
    }
    int live_writable = show_live_access();
    if (!check && !live_writable) {
        fprintf(stderr, "The OS refused a writable file descriptor. No write transaction was started.\n");
        return 1;
    }
    sqlite3 *db = open_db(WLOC_LIVE_DB, check ? SQLITE_OPEN_READONLY : SQLITE_OPEN_READWRITE);
    if (!db) return 1;
    show_journal_mode(db);
    if (!check) printf("SQLite write connection readonly: %d\n", sqlite3_db_readonly(db, "main"));
    int count = 0;
    int ok = (check || execute(db, "BEGIN IMMEDIATE")) && inspect(db, &count);
    if (ok && check) {
        printf("Target rule: %s\n", count ? "present" : "absent");
    } else if (ok && count == applying) {
        ok = applying ? apply(db) : restore(db);
        int after = -1;
        ok = ok && scalar(db, "SELECT count(*) FROM rules WHERE " MATCH, &after) && after == !applying;
        ok = ok && execute(db, "COMMIT");
        if (ok) printf("%s. Restart iPhone to validate with trustd.\n", applying ? "Applied" : "Restored");
    } else if (ok) {
        printf("Target rule is already %s.\n", applying ? "absent" : "present");
    }
    if (!sqlite3_get_autocommit(db)) execute(db, "ROLLBACK");
    sqlite3_close(db);
    return ok ? 0 : 1;
}
