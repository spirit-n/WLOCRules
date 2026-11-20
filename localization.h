#pragma once

void wloc_set_language(const char *language);
const char *wloc_language(void);
const char *wloc_text(const char *english, const char *simplified_chinese);
const char *wloc_system_error(int error);
const char *wloc_sqlite_error(int error, const char *detail);
