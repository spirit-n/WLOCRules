# WLOCRules

WLOCRules 是一个通过 TrollStore 安装的 iOS 工具，用于检查、移除和恢复 `trustd` 规则库里与 WLOC 有关的单条证书固定规则。规则匹配 `gs-loc.apple.com` 和 `gs-loc-cn.apple.com`。应用修改会改变这两个域名的证书校验行为。

## 兼容性

- 数据库要求 **content 131、schema 3**。工具在写入前校验版本、完整性及目标规则。
- v1.3 曾在 iPhone 13 Pro Max、iOS 15.7、受信任资产 33 上完成修改并重启验证。iOS 15.0 是构建目标，实际写入还取决于 TrollStore 和设备上的 `trustd` 存储权限。
- 系统更新信任资产后可能重新写入规则。遇到这个情况，先重新运行「检查」核对版本和规则状态。

## 使用

1. 使用 TrollStore 安装自行构建的 `.tipa`。[TrollStore 项目](https://github.com/opa334/TrollStore)
2. 点击 **检查（只读）**，查看规则状态和写权限。`Target rule: present` 表示规则存在。若日志显示系统拒绝打开数据库进行读写，请先排查权限。
3. 点击 **应用修改**。工具会先在 `/private/var/root/wloc-pinning-v131.sqlite3` 保存备份，再通过 SQLite 事务删除目标规则。
4. 重启 iPhone，再点「检查」。`Target rule: absent` 表示规则仍处于移除状态。此时可测试 WLOC 和苹果地图的实际表现。

需要还原时点击 **恢复规则**，然后重启并检查 `Target rule: present`。恢复只从备份补回目标规则。若系统已经把规则恢复，工具会提示规则已存在。

## 从源码构建

在 Linux 或 WSL 2 中准备 Bash、Clang 18、LLD 18 和 iOS 15.6 SDK。打包需要 Python 3 和支持 DER entitlements 的 ldid。[ldid 发行页](https://github.com/ProcursusTeam/ldid/releases)

以下命令从项目根目录执行，SDK 会放在项目旁边。已有 SDK 时，可以通过 `WLOC_SDK` 指定其目录。

```sh
git clone --filter=blob:none --no-checkout https://github.com/theos/sdks.git ../ios-sdks
git -C ../ios-sdks config core.autocrlf false
git -C ../ios-sdks config core.symlinks true
git -C ../ios-sdks sparse-checkout set iPhoneOS15.6.sdk
git -C ../ios-sdks checkout --detach 0222fd5413cf4b9af096f37b4621afa2688572f7
bash build.sh
python3 package.py WLOCRules.tipa
```

`package.py` 默认从 `PATH` 查找 `ldid`，也可通过 `--ldid` 或 `WLOC_LDID` 指定。若在 WSL 编译并使用 Windows 版 `ldid`，可从资源管理器打开项目目录，再从 PowerShell 执行以下命令。

```powershell
python .\package.py --ldid 'C:\path\to\ldid.exe' WLOCRules.tipa
```

打包会核对 arm64 Mach-O、iOS 部署目标、XML/DER 签名项目和归档权限，随后打印 SHA-256。请为每次打包指定一个新文件名。

## 测试

在 Linux 或 WSL 中使用 GCC、Python 3 和 SQLite 开发包（Ubuntu 的 `libsqlite3-dev`）。测试使用临时数据库，覆盖备份、修改、恢复、重复执行、锁冲突、符号链接和 WAL。`sudo` 用于验证 helper 的 root 检查。

```sh
sudo python3 test_rules.py
```

可以加上 `--sample /path/to/original.sqlite3`，让测试使用自己保存的原始数据库副本。项目使用 `.gitignore` 排除数据库、签名工具和安装包。

## 参考

- [wloc 项目](https://github.com/Yu9191/wloc) · [规则库调查 #130](https://github.com/Yu9191/wloc/issues/130) · [TrollStore 方案讨论 #173](https://github.com/Yu9191/wloc/issues/173)
- [Apple 的 trustd 证书固定实现](https://github.com/apple-oss-distributions/Security/blob/Security-60158.140.3/trust/trustd/SecPinningDb.m)
