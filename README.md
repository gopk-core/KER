# KER

一个 Linux 内核级授权系统：把经过签名的密钥放在可移动介质上，在终端里完成安装与管理。没有图形界面。

[English](README_EN.md)

当前版本：**0.1**（首个公开发布）。许可证：[GNU Affero General Public License v3.0](LICENSE)。

## 安全须知（请先读）

- **不要**在已经运行另一套内核防护（例如本机上的 `ker-guard`）的生产主机上安装 KER 软件包，也不要在该主机上加载新的 BPF，或重建其 initramfs。
- 内核拦截默认关闭，且**不会**因安装或升级软件包而自动打开。只有在介质校验通过后，由管理员显式执行 `ker enforce --set enforce --yes` 才会启用。裸机默认拒绝加载 BPF；若确有需要，必须显式设置 `KER_ALLOW_HOST_BPF=1`。
- 即使没有 Secure Boot 或内核 lockdown，KER 也不能阻止已经拿到 root 的人替换内核或引导程序。它提供的是带签名介质的授权与可选的 LSM 拦截，不是固件级信任根。
- `boot.pem` 的早期启动挂钩在强制模式下失败即关闭（fail-closed）：缺介质或校验失败会拒绝进入真实根文件系统。不要削弱这一策略。

## KER 是什么

KER 用外部介质（U 盘、可移动硬盘、DVD、WORM 等）携带经过签名的权限密钥，在系统启动、登录和运行时决定机器是否被授权执行相应操作。

典型用途：

- 机器必须插入带签名的启动介质，才能进入真实根文件系统；
- 运行时根据介质在位情况，可选地在内核 LSM 层拦截读、写、执行、网络等操作；
- 多台机器组成主从集群，策略由主节点签名并同步；子节点在失联时失败关闭。

首次运行 `ker` 会进入终端向导（可选 English / 简体中文 / 繁体中文），必须使用 root。

## 介质与密钥如何工作

- 列出全部可识别的块设备（不只是 U 盘），确认后格式化并写入密封文件集合。
- 可反复写的移动介质用 FAT32，硬盘用 ext4，DVD-R 写 ISO9660 镜像；WORM 只在介质为空时写入，不会重新格式化。
- 每把密钥 10MB。`root.pem` 只签名不加密，其它密钥先加密再签名；解密材料来自 `root.pem` 中的固定段。没有根密钥，任何权限都不能成立。
- 解密后的材料尽量放入内核密钥环，不以明文写进普通目录。
- 默认单介质；也可以把密钥分配到多张盘，每张盘单独签名。管理密钥 `admin.pem` 用于 `ker console`。
- 写盘后进入测试模式：只在终端报告校验结果，不启用内核拦截。可选要求插拔验收。

## 从软件包安装

软件包按架构构建（不再使用 `Architecture: all`），因为其中包含该架构的 BPF 对象和 `ker-probe`。发布区提供 `.deb`、`.rpm`、`.apk` 和 `.pkg.tar.zst`，架构包括 amd64、arm64、armhf、i386、riscv64。

把对应架构的包拷到目标机器后：

```bash
sudo dpkg -i ker_0.1_amd64.deb
# 或
sudo rpm -Uvh ker-0.1-1.x86_64.rpm
sudo apk add --allow-untrusted ker-0.1-r0.x86_64.apk
sudo pacman -U ker-0.1-1-x86_64.pkg.tar.zst
```

装好后 `/usr/sbin/ker` 已在 root 的 PATH 中，直接运行 `ker` 进入首次向导。

未签名的本地包如果走 `ker upgrade --trust-package`，仍需要该开关。依赖大致包括 Python 3、python3-cryptography、GnuPG、openssl、dosfstools、e2fsprogs、xorriso、util-linux、keyutils、bpftool。完整矩阵见 [docs/packaging.md](docs/packaging.md)。

## 升级（只手动，无自动更新）

KER 不会自行检查或安装新版本。把新包装到机器上后执行上面的包管理器命令，或：

```bash
sudo ker upgrade --trust-package ./ker_0.1_amd64.deb
```

新包会接替旧包：密钥、介质、策略和运行模式保留，并自动做完所需的状态迁移。升级**不会**打开或关闭内核拦截，也不会改写已密封的介质。新增功能由新包直接提供；需要新密钥的功能要在之后签发，不会在升级时写入旧盘。

只查看计划：`ker upgrade --check`。已换成新程序、只补迁移：`ker upgrade --migrate`。恢复最近一次升级快照：`ker upgrade --rollback`。

完整契约见 [docs/upgrade.md](docs/upgrade.md)。

0.1 是首个公开发布。如果状态里已经打开了内核拦截，重启后会自动恢复并重新挂上 BPF（通过 `ker-enforcer.service`）。从未选择打开拦截的主机，不会因此被启用。

## 启动挂钩（boot.pem，失败即关闭）

`boot.pem` 提供 initramfs-tools / dracut / mkinitcpio / mkinitfs 的早期启动挂钩。强制模式下，缺介质或校验失败会拒绝进入真实根文件系统，并在控制台给出原因。测试模式只记录、不拦截。

SSH 挂钩（PAM account 与 `AuthorizedKeysCommand`）同样遵循该模式：强制模式下缺 `ssh.pem` 则拒绝密码和公钥登录；测试模式只记录。说明见 [docs/hooks.md](docs/hooks.md)。

## 运行时拦截与介质在位

测试模式是默认。介质校验通过且管理员确认后，可在虚拟机（或显式允许的主机）里加载 BPF LSM。

打开强制模式之后：

- `ker enforce --watch` 由 systemd 服务长期运行，并在开机时自动拉起，以便恢复 BPF 映射；
- udev 会在块设备插拔时立即做一次在位检查；另有定时器作为备份；
- **先拒绝、再校验**：拔出所需介质会立刻把 `media_ok` 置 0，不需要等挂载或验签结束；重新插入并校验通过后再允许；
- 强制模式不会因为软件包安装或升级而自动打开。关闭：`ker enforce --set test`。

## 集群、控制台与卸载

- 主从集群：`ker addnet` / `ker token` / `ker serve`，使用签名令牌与策略同步。主机失联时，子节点失败关闭。
- 控制台与密钥轮换：`ker console`（需要管理员介质）。轮换后原子切换并通知子节点。
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
