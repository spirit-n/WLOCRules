#include "localization.h"
#include <errno.h>
#include <string.h>

static int simplified_chinese;

void wloc_set_language(const char *language) {
    simplified_chinese = language && strcmp(language, "zh-Hans") == 0;
}

const char *wloc_language(void) {
    return simplified_chinese ? "zh-Hans" : "en";
}

const char *wloc_text(const char *english, const char *chinese) {
    return simplified_chinese ? chinese : english;
}

const char *wloc_system_error(int error) {
    if (!simplified_chinese) return strerror(error);
    switch (error) {
        case 0: return "成功";
        case EPERM: return "系统不允许此操作";
        case EACCES: return "权限不足";
        case ENOENT: return "文件或目录不存在";
        case EEXIST: return "文件已存在";
        case EROFS: return "文件系统为只读";
        case EBUSY: return "资源正忙";
        case EAGAIN: return "资源暂时不可用";
        case EINVAL: return "参数无效";
        case ENOSPC: return "存储空间不足";
        case EIO: return "输入输出错误";
        case EINTR: return "操作被中断";
        case ENOMEM: return "内存不足";
        case EMFILE: return "进程打开的文件过多";
        case ENFILE: return "系统打开的文件过多";
        case ENOTDIR: return "路径中的某一项不是目录";
        case EISDIR: return "目标是目录";
        case ELOOP: return "路径包含符号链接或链接循环";
        case ENAMETOOLONG: return "路径名称过长";
        case ESRCH: return "目标进程不存在";
        case ECHILD: return "子进程不存在";
        default: return "系统调用失败";
    }
}

const char *wloc_sqlite_error(int error, const char *detail) {
    static const char *const descriptions[] = {
        "成功", "SQL 错误或数据库结构不符合要求", "SQLite 内部错误", "访问被拒绝",
        "操作已终止", "数据库正忙", "数据库已锁定", "内存不足", "数据库为只读",
        "操作被中断", "数据库输入输出错误", "数据库已损坏", "找不到所需对象",
        "存储空间不足", "无法打开数据库", "数据库锁协议错误", "数据库为空",
        "数据库结构已改变", "数据过大", "数据库约束冲突", "数据类型不匹配",
        "SQLite 调用方式错误", "不支持的大文件操作", "操作未获授权",
        "辅助数据库格式错误", "绑定参数超出范围", "文件不是有效的 SQLite 数据库"
    };
    if (!simplified_chinese) return detail;
    unsigned primary = (unsigned)error & 0xff;
    return primary < sizeof(descriptions) / sizeof(descriptions[0])
        ? descriptions[primary] : "数据库操作失败";
}
