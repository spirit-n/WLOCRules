#include "helper.h"
#include "localization.h"
#include <stddef.h>
#include <string.h>

const char *wloc_helper_command(int argc, char *const argv[]) {
    if (argc != 2 && argc != 3) return NULL;
    const char *separator = strchr(argv[1], ':');
    size_t length = separator ? (size_t)(separator - argv[1]) : strlen(argv[1]);
    const char *language = argc == 3 ? argv[2] : "en";
    if (separator) {
        if (argc != 2) return NULL;
        language = separator + 1;
        if (strcmp(language, "en") != 0 && strcmp(language, "zh-Hans") != 0) return NULL;
    }
    static const char *const commands[] = {"check", "apply", "restore"};
    for (size_t index = 0; index < sizeof(commands) / sizeof(commands[0]); index++) {
        if (strlen(commands[index]) == length && strncmp(commands[index], argv[1], length) == 0) {
            wloc_set_language(language);
            return commands[index];
        }
    }
    return NULL;
}
