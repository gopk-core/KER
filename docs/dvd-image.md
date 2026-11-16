# DVD-R 授权介质（0.1.0）

KER 0.1.0 写到 DVD-R 上的是一张数据盘，不是可启动的操作系统盘。刻录后不会自动安装 KER，也不会自行打开内核拦截。

介质上被签名的对象是 `bundle.json`：

- `schema` 为 2。
- `expiry_policy` 为 `never`，`expires` 为 `null`。没有日期到期限制，也不再使用 2029 年证书。
- `bundle.json.sig` 是 GPG 分离签名，`bundle.json.ksig` 是 OpenSSL RSA 签名。
- pem 文件列在 `bundle.json` 的哈希表里。它们没有各自的签名。
- `root.pem` 不加密。其它密钥先加密再列入哈希表。持有 `root.pem` 可以解开这些密钥；清单签名不能对持有根密钥的人提供保密。

GPG 签名密钥按 `Expire-Date: 0` 生成，没有到期日。内核验签材料是长期 X.509 证书（`openssl req -days 365000`），用来校验 `bundle.json.ksig`，不是一份 2029 年到期的证书，也不是“每把 pem 一张证书”。

本仓库不附带某一张已刻录光盘的字节大小或 SHA-256。那些数值属于某次本地刻录，不是 0.1.0 的发布物。当前策略以源码为准：`python/ker/bundle.py` 写 `expiry_policy=never`，`python/ker/sign.py` 生成无到期日的 GPG 密钥和上述长期证书。

刻录：

1. 用 `ker` 初始化或轮换时选择 DVD-R。KER 在 `var/lib/ker` 下生成该介质的 ISO9660 镜像。
2. 用标准单层 DVD-R，按“刻录光盘映像”写入 ISO，不要把 ISO 当普通文件拷进光盘。
3. 不解压介质里的密钥文件；关闭多区段。刻录后做回读校验。
4. 无到期日不等于光盘本身不会损坏。

镜像或公钥上的不可变标记只能防止误改，不能阻止已经拿到 root 的人绕过。没有 Secure Boot 时，KER 也不是固件级信任根。
