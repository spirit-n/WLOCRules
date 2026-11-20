#import <UIKit/UIKit.h>
#include <stdio.h>
#include <errno.h>
#include <spawn.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include "rules.h"
#include "localization.h"
#include "helper.h"

static NSString *localized(const char *english, const char *chinese) {
    return [NSString stringWithUTF8String:wloc_text(english, chinese)];
}

extern int posix_spawnattr_set_persona_np(const posix_spawnattr_t *, uid_t, uint32_t);
extern int posix_spawnattr_set_persona_uid_np(const posix_spawnattr_t *, uid_t);
extern int posix_spawnattr_set_persona_gid_np(const posix_spawnattr_t *, gid_t);

typedef struct __SecTask *HelperSecTaskRef;
extern HelperSecTaskRef SecTaskCreateFromSelf(CFAllocatorRef);
extern CFTypeRef SecTaskCopyValueForEntitlement(HelperSecTaskRef, CFStringRef, CFErrorRef *);

static void show_trustd_entitlements(void) {
    HelperSecTaskRef task = SecTaskCreateFromSelf(kCFAllocatorDefault);
    CFTypeRef paths = task ? SecTaskCopyValueForEntitlement(task,
        CFSTR("com.apple.security.exception.files.absolute-path.read-write"), NULL) : NULL;
    int valid = paths && CFGetTypeID(paths) == CFArrayGetTypeID() &&
        CFArrayContainsValue((CFArrayRef)paths, CFRangeMake(0, CFArrayGetCount((CFArrayRef)paths)),
                             CFSTR("/private/var/protected/trustd/"));
    fprintf(stderr, wloc_text("Installed trustd path entitlement: %s\n", "已安装的 trustd 路径权限：%s\n"),
            valid ? wloc_text("present", "存在") : wloc_text("not reported", "未检测到"));
    if (paths) CFRelease(paths);
    CFTypeRef storage = task ? SecTaskCopyValueForEntitlement(task,
        CFSTR("com.apple.private.security.storage.trustd"), NULL) : NULL;
    fprintf(stderr, wloc_text("Installed trustd storage entitlement: %s\n", "已安装的 trustd 存储权限：%s\n"),
            storage && CFEqual(storage, kCFBooleanTrue)
                ? wloc_text("present", "存在") : wloc_text("not reported", "未检测到"));
    if (storage) CFRelease(storage);
    if (task) CFRelease(task);
}

static NSString *run_helper(NSString *command, BOOL *success) {
    *success = NO;
    int output[2];
    if (pipe(output) != 0) return [NSString stringWithFormat:localized("Create output pipe: %s (%d)",
            "创建日志管道失败：%s（%d）"), wloc_system_error(errno), errno];
    posix_spawnattr_t attributes;
    posix_spawn_file_actions_t actions;
    int error = posix_spawnattr_init(&attributes);
    BOOL haveAttributes = error == 0;
    if (!error) error = posix_spawnattr_set_persona_np(&attributes, 99, 1);
    if (!error) error = posix_spawnattr_set_persona_uid_np(&attributes, 0);
    if (!error) error = posix_spawnattr_set_persona_gid_np(&attributes, 0);
    BOOL haveActions = NO;
    if (!error) {
        error = posix_spawn_file_actions_init(&actions);
        haveActions = error == 0;
    }
    if (!error) error = posix_spawn_file_actions_adddup2(&actions, output[1], STDOUT_FILENO);
    if (!error) error = posix_spawn_file_actions_adddup2(&actions, output[1], STDERR_FILENO);
    if (!error) error = posix_spawn_file_actions_addclose(&actions, output[0]);
    if (!error) error = posix_spawn_file_actions_addclose(&actions, output[1]);
    NSString *path = NSBundle.mainBundle.executablePath;
    NSString *helperCommand = [NSString stringWithFormat:@"%@:%s", command, wloc_language()];
    char *arguments[] = {(char *)path.fileSystemRepresentation, (char *)helperCommand.UTF8String, NULL};
    char *environment[] = {NULL};
    pid_t child = 0;
    if (!error) error = posix_spawn(&child, arguments[0], &actions, &attributes, arguments, environment);
    if (haveActions) posix_spawn_file_actions_destroy(&actions);
    if (haveAttributes) posix_spawnattr_destroy(&attributes);
    close(output[1]);
    if (error) {
        close(output[0]);
        return [NSString stringWithFormat:localized("Cannot start root helper (%d)\n%s",
                "无法启动 root 辅助进程（%d）\n%s"), error, wloc_system_error(error)];
    }
    const NSUInteger logLimit = 16 * 1024;
    NSMutableData *data = [NSMutableData data];
    BOOL truncated = NO;
    char buffer[1024];
    ssize_t length;
    do {
        length = read(output[0], buffer, sizeof(buffer));
        if (length > 0) {
            NSUInteger available = MIN((NSUInteger)length, logLimit - data.length);
            [data appendBytes:buffer length:available];
            truncated |= available < (NSUInteger)length;
        }
    } while (length > 0 || (length == -1 && errno == EINTR));
    int readError = length < 0 ? errno : 0;
    close(output[0]);
    int status = 0;
    pid_t waited;
    do { waited = waitpid(child, &status, 0); } while (waited == -1 && errno == EINTR);
    int waitError = waited == -1 ? errno : 0;
    *success = !readError && waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
    NSString *log = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!log && truncated) {
        // The byte limit may split a UTF-8 character at the end of the log.
        for (NSUInteger removed = 1; removed <= 3 && !log; removed++) {
            log = [[NSString alloc] initWithBytes:data.bytes length:data.length - removed
                                         encoding:NSUTF8StringEncoding];
        }
    }
    if (!log) log = localized("Helper output is not valid UTF-8.", "辅助进程日志不是有效的 UTF-8 文本。");
    if (truncated) log = [log stringByAppendingString:localized("\nHelper output truncated.", "\n辅助进程日志已截断。")];
    if (readError) log = [log stringByAppendingFormat:localized("\nRead helper output: %s (%d)",
            "\n读取辅助进程日志失败：%s（%d）"), wloc_system_error(readError), readError];
    if (waitError) {
        log = [log stringByAppendingFormat:localized("\nWait for helper: %s (%d)",
                "\n等待辅助进程失败：%s（%d）"), wloc_system_error(waitError), waitError];
    } else if (WIFSIGNALED(status)) {
        log = [log stringByAppendingFormat:localized("\nHelper exited on signal %d",
                "\n辅助进程因信号 %d 退出"), WTERMSIG(status)];
    }
    return log;
}

@interface RulesController : UIViewController
@property(nonatomic) UITextView *logView;
@property(nonatomic) NSArray<UIButton *> *buttons;
@end

@implementation RulesController

- (UIButton *)button:(NSString *)title action:(SEL)action {
    UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
    UIButtonConfiguration *config = [UIButtonConfiguration tintedButtonConfiguration];
    config.title = title;
    button.configuration = config;
    [button addTarget:self action:action forControlEvents:UIControlEventTouchUpInside];
    [button.heightAnchor constraintGreaterThanOrEqualToConstant:48].active = YES;
    return button;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = UIColor.systemBackgroundColor;
    UILabel *title = [UILabel new];
    title.text = [NSString stringWithFormat:@"%@ %@", localized("WLOC Rules", "WLOC 规则工具"),
                  NSBundle.mainBundle.infoDictionary[@"CFBundleShortVersionString"]];
    title.font = [UIFont preferredFontForTextStyle:UIFontTextStyleTitle1];
    UILabel *detail = [UILabel new];
    detail.text = localized("For rules database v131. Apply saves a backup first. Restore only adds back the target rule.",
                            "适用于规则库 v131。应用前会备份当前数据库，恢复时只补回这条规则。");
    detail.font = [UIFont preferredFontForTextStyle:UIFontTextStyleBody];
    detail.numberOfLines = 0;
    self.buttons = @[[self button:localized("Check (read-only)", "检查（只读）") action:@selector(checkRules)],
                     [self button:localized("Apply changes", "应用修改") action:@selector(applyRules)],
                     [self button:localized("Restore rule", "恢复规则") action:@selector(restoreRules)]];
    self.logView = [UITextView new];
    self.logView.editable = NO;
    self.logView.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightRegular];
    self.logView.backgroundColor = UIColor.secondarySystemBackgroundColor;
    self.logView.text = localized("Start with Check (read-only).", "安装后请先点「检查（只读）」。");
    NSMutableArray<UIView *> *items = [NSMutableArray arrayWithArray:@[title, detail]];
    [items addObjectsFromArray:self.buttons];
    [items addObject:self.logView];
    UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:items];
    stack.axis = UILayoutConstraintAxisVertical;
    stack.spacing = 12;
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:stack];
    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [stack.topAnchor constraintEqualToAnchor:safe.topAnchor constant:20],
        [stack.bottomAnchor constraintEqualToAnchor:safe.bottomAnchor constant:-16],
        [stack.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:20],
        [stack.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-20]
    ]];
}

- (void)run:(NSString *)command {
    for (UIButton *button in self.buttons) button.enabled = NO;
    self.logView.text = localized("Processing database…", "正在处理数据库…");
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        BOOL ok;
        NSString *log = run_helper(command, &ok);
        dispatch_async(dispatch_get_main_queue(), ^{
            self.logView.text = [NSString stringWithFormat:localized("App: WLOCRules %@ · %s\n%@\n\n%@",
                                                                   "应用：WLOCRules %@ · %s\n%@\n\n%@"),
                NSBundle.mainBundle.infoDictionary[@"CFBundleShortVersionString"], wloc_language(),
                ok ? localized("Operation completed", "操作完成") : localized("Operation failed", "操作失败"), log];
            for (UIButton *button in self.buttons) button.enabled = YES;
        });
    });
}

- (void)checkRules { [self run:@"check"]; }

- (void)confirm:(NSString *)command title:(NSString *)title message:(NSString *)message {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:title message:message
        preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:localized("Cancel", "取消") style:UIAlertActionStyleCancel handler:nil]];
    [alert addAction:[UIAlertAction actionWithTitle:localized("Continue", "继续") style:UIAlertActionStyleDefault
        handler:^(__unused UIAlertAction *action) { [self run:command]; }]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)applyRules {
    [self confirm:@"apply" title:localized("Apply changes?", "应用修改？")
        message:localized("Back up the current database and remove the additional certificate pinning rule for gs-loc.apple.com and gs-loc-cn.apple.com.",
                          "备份当前数据库，并移除 gs-loc.apple.com 和 gs-loc-cn.apple.com 的额外证书固定规则。")];
}

- (void)restoreRules {
    [self confirm:@"restore" title:localized("Restore rule?", "恢复规则？")
        message:localized("Restore the original location-domain rule from the backup.", "从备份补回原来的定位域名规则。")];
}
@end

@interface AppDelegate : UIResponder <UIApplicationDelegate>
@property(nonatomic) UIWindow *window;
@end

@implementation AppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)options {
    (void)application;
    (void)options;
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.window.rootViewController = [RulesController new];
    [self.window makeKeyAndVisible];
    return YES;
}
@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        const char *command = wloc_helper_command(argc, argv);
        if (command) {
            NSString *version = NSBundle.mainBundle.infoDictionary[@"CFBundleShortVersionString"] ?: @"unknown";
            fprintf(stderr, wloc_text("Helper: WLOCRules %s · %s\n", "辅助进程：WLOCRules %s · %s\n"),
                    version.UTF8String, wloc_language());
            if (geteuid() == 0) show_trustd_entitlements();
            return run_rules_command(command);
        }
        NSString *language = NSLocale.preferredLanguages.firstObject ?: @"en";
        NSDictionary *parts = [NSLocale componentsFromLocaleIdentifier:language];
        NSString *script = parts[NSLocaleScriptCode];
        NSString *region = parts[NSLocaleCountryCode];
        BOOL chinese = [parts[NSLocaleLanguageCode] isEqualToString:@"zh"] &&
            ([script isEqualToString:@"Hans"] || (!script &&
                ([region isEqualToString:@"CN"] || [region isEqualToString:@"SG"])));
        wloc_set_language(chinese ? "zh-Hans" : "en");
        return UIApplicationMain(argc, argv, nil, NSStringFromClass(AppDelegate.class));
    }
}
