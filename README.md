# KER

<p align="center">
  <img src="docs/logo.png" alt="KER" width="160" height="160">
</p>

一个 Linux 内核级授权系统：把经过签名的密钥放在可移动介质上，在终端里完成安装与管理。没有图形界面。

[English](README_EN.md)

当前版本：**0.1.0**（首个公开发布；已发布的 `0.1` 与 `0.1.0` 数值相等，可直接升级）。许可证：[GNU Affero General Public License v3.0](LICENSE)。

## 安全须知（请先读）

- **不要**在已经运行另一套内核防护（例如本机上的 `ker-guard`）的生产主机上安装 KER 软件包，也不要在该主机上加载新的 BPF，或重建其 initramfs。
- 内核拦截默认关闭，且**不会**因安装或升级软件包而自动打开。只有在介质校验通过后，由管理员显式执行 `ker enforce --set enforce --yes` 才会启用。裸机默认拒绝加载 BPF；若确有需要，必须显式设置 `KER_ALLOW_HOST_BPF=1`。
- 即使没有 Secure Boot 或内核 lockdown，KER 也不能阻止已经拿到 root 的人替换内核或引导程序。它提供的是带签名介质的授权与可选的 LSM 拦截，不是固件级信任根。
- `boot.pem` 的早期启动挂钩在强制模式下失败即关闭（fail-closed）：缺介质或校验失败会拒绝进入真实根文件系统。不要削弱这一策略。

## 免责声明

KER 按现状提供，源码已经公开。作者和贡献者不对使用本软件造成的任何损失承担责任，包括但不限于设备无法启动、无法登录、系统死锁、数据无法访问或业务中断。

一旦启用强制模式、启动挂钩或运行时拦截，出现下列情况时，机器可能拒绝进入系统、拒绝登录，或立即拒绝包括 root 在内的用户指令：所需介质缺失、损坏、丢失或无法读取；校验失败；设备故障；配置错误；操作不当。由此产生的后果由使用者自行承担。使用前请自行评估风险，并自行准备可恢复的应急方案。

## KER 是什么

KER 用外部介质（U 盘、可移动硬盘、DVD、WORM 等）携带经过签名的权限密钥，在系统启动、登录和运行时决定机器是否被授权执行相应操作。

典型用途：

- 机器必须插入带签名的启动介质，才能进入真实根文件系统；
- 运行时根据介质在位情况，可选地在内核 LSM 层拦截读、写、执行、网络等操作；
- 多台机器组成主从集群，策略由主节点签名并同步；子节点在失联时失败关闭。

首次运行 `ker` 会进入终端向导（可选 English / 简体中文 / 繁体中文），必须使用 root。

## 介质与密钥如何工作

- 列出全部可识别的块设备（不只是 U 盘），确认后格式化并写入密封文件集合。
- 可反复写的移动介质用 FAT32，硬盘用 ext4，DVD-R 写 ISO9660 镜像；WORM 只在介质为空时写入，不会重新格式化。光盘只是数据盘，说明见 [docs/dvd-image.md](docs/dvd-image.md)。
- 每把密钥 10MB。被签名的对象是介质上的 `bundle.json`（密钥哈希清单）：一份 GPG 分离签名（`bundle.json.sig`）加一份 OpenSSL RSA 签名（`bundle.json.ksig`）。pem 文件本身没有单独的签名，完整性靠清单里的哈希。`root.pem` 不加密；其它密钥先用 `root.pem` 里的固定段加密，再写入清单。这不是“每把 pem 各签一次”。持有 `root.pem` 的人可以解开其它密钥，KER 不声称能对持有根密钥的人保密。没有根密钥，任何权限都不能成立。
- 解密后的材料尽量放入内核密钥环，不以明文写进普通目录。
- 默认单介质；也可以把密钥分配到多张盘，每张盘单独签名。管理密钥 `admin.pem` 用于 `ker console`。
- 写盘后进入测试模式：只在终端报告校验结果，不启用内核拦截。可选要求插拔验收。

## 从软件包安装

软件包按架构构建（不再使用 `Architecture: all`），因为其中包含该架构的 BPF 对象和 `ker-probe`。发布区提供 `.deb`、`.rpm`、`.apk` 和 `.pkg.tar.zst`，架构包括 amd64、arm64、armhf、i386、riscv64。

把对应架构的包拷到目标机器后：

```bash
sudo dpkg -i ker_0.1.0_amd64.deb
# 或
sudo rpm -Uvh ker-0.1.0-1.x86_64.rpm
sudo apk add --allow-untrusted ker-0.1.0-r0.x86_64.apk
sudo pacman -U ker-0.1.0-1-x86_64.pkg.tar.zst
```

装好后 `/usr/sbin/ker` 已在 root 的 PATH 中，直接运行 `ker` 进入首次向导。

安装包带上公钥 `release.gpg`（`/usr/lib/ker/release-keys/release.gpg`）。构建机只有在设置了离线私钥目录 `KER_RELEASE_GNUPGHOME` 时才给产物做分离签名；没有私钥的 CI 仍生成未签名包。`ker upgrade` 会用公钥校验 `<包>.sig`。没有签名时必须显式加 `--trust-package`；签名对不上公钥则直接拒绝。私钥、口令和密钥环都不得进入 git。依赖大致包括 Python 3、python3-cryptography、GnuPG、openssl、dosfstools、e2fsprogs、xorriso、util-linux、keyutils、bpftool。完整矩阵见 [docs/packaging.md](docs/packaging.md)。

## 升级（只手动，无自动更新）

KER 不会自行检查或安装新版本。把新包装到机器上后执行上面的包管理器命令，或：

```bash
sudo ker upgrade ./ker_0.1.0_amd64.deb
# 本地未签名包才需要：
# sudo ker upgrade --trust-package ./ker_0.1.0_amd64.deb
```

新包会接替旧包：密钥、介质、策略和运行模式保留，并自动做完所需的状态迁移。升级**不会**打开或关闭内核拦截，也不会改写已密封的介质。新增功能由新包直接提供；需要新密钥的功能要在之后签发，不会在升级时写入旧盘。

只查看计划：`ker upgrade --check`。已换成新程序、只补迁移：`ker upgrade --migrate`。恢复最近一次升级快照：`ker upgrade --rollback`。

完整契约见 [docs/upgrade.md](docs/upgrade.md)。

0.1.0 是首个公开发布的版本号（与已发布的 0.1 数值相等）。如果状态里已经打开了内核拦截，重启后会自动恢复并重新挂上 BPF（通过 `ker-enforcer.service`）。从未选择打开拦截的主机，不会因此被启用。

## 启动挂钩（boot.pem，失败即关闭）

`boot.pem` 提供 initramfs-tools / dracut / mkinitcpio / mkinitfs 的早期启动挂钩。强制模式下，缺介质或校验失败会拒绝进入真实根文件系统，并在控制台给出原因。测试模式只记录、不拦截。

SSH 挂钩（PAM account 与 `AuthorizedKeysCommand`）同样遵循该模式：强制模式下缺 `ssh.pem` 则拒绝密码和公钥登录；测试模式只记录。说明见 [docs/hooks.md](docs/hooks.md)。

## 运行时拦截与介质在位

测试模式是默认。介质校验通过且管理员确认后，可在虚拟机（或显式允许的主机）里加载 BPF LSM。

打开强制模式之后：

- `ker enforce --watch` 由 systemd 服务长期运行，并在开机时自动拉起，以便恢复 BPF 映射；
- udev 会在块设备插拔时立即做一次在位检查；另有定时器作为备份；
- **按介质对应到权限位**：`ssh.pem` 所在的盘缺失或验签失败，只拒绝 SSH；读、写、执行、网络、root 登录仍由各自的密钥盘决定。`root.pem` 是全部权限的前提，根介质缺失会拒绝全部已选运行时权限。`boot.pem` 只作用于早期启动挂钩，`admin.pem` 只作用于 `ker console`。
- **自定义规则不放大成整机权限**。带路径、用户、端口或单元约束的规则只作用于被点名的对象。约束无法精确核对时，该规则不授权任何对象，也不会变成全局的执行、读写或网络位。
- **先拒绝、再校验**：拔出某张运行时所需介质会立刻清掉它对应的权限位，不等待挂载或验签；重新插入并校验通过后只恢复这些位。
- 强制模式不会因为软件包安装或升级而自动打开。关闭：`ker enforce --set test`。

## 集群、控制台与卸载

- 主从集群：`ker addnet` / `ker token` / `ker serve`。加入时必须带上带外确认的信任指纹（`ker addnet --fingerprint`），或由本机已经校验过的根/管理介质证明；节点不会把令牌里自带的信任锚直接装上再拿它验自己。主机失联时，子节点失败关闭。
- 控制台与密钥轮换：`ker console`（需要管理员介质）。轮换会先卸下内核拦截。写完介质后，在新盘验签通过之前不会把 `media_ok` 打开；验签失败则保持失败关闭（拦截可以仍是开启的，但已选权限位留在拒绝掩码里）。BPF 映射和 `ker-enforcer` 单元与这个结果一致。
- 丢失的盘：`ker revoke-medium --drop` 或 `--replace /dev/...`，也可以写 `ker console revoke-medium`。证明是仍然在位的根介质，或在根介质本身丢失时用管理介质。根介质还在时，不要求再插一张管理盘。根介质和管理介质都没有时，命令失败关闭，不能在没有证明的情况下吊销。轮换后的新签名使旧盘不再被接受。没有单独的吊销列表。
- 卸载：`ker uninstall` 需要 root，并验齐根介质和全部权限介质。主节点可向在线子节点下发签名卸载；离线子节点需在本地卸载。

## 构建与测试

在源码树中构建即可，不必在构建机上安装 KER：

```bash
make test
make packages          # deb + rpm + apk + pkg.tar.zst，五种架构
make deb               # 只构建 .deb
ARCHES=amd64 make deb  # 只构建当前测试用的 amd64 deb
```

生成的包在 `dist/`。虚拟机自测：`sudo bash scripts/vm-test.sh`（不会把包装到宿主机，也不会在宿主机加载 BPF）。


## 赞助

如果这个项目对你有帮助，欢迎赞助，以支持后续维护。

### 微信支付 WeChat

![微信支付](docs/sponsors/weixin.png)

### 支付宝 Alipay

![支付宝](docs/sponsors/alipay.jpg)
