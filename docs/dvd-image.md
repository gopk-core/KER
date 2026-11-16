# DVD-R and optical media (0.1.0)

KER can seal a key set onto DVD-R or another optical device. The disc is a data image. It is not a bootable operating system and it does not install KER. Burning it does not enable kernel enforcement.

## What is written

The signed object is `bundle.json` (media schema 2):

- `expiry_policy` is `never` and `expires` is null. There is no date limit.
- `bundle.json.sig` is a detached GnuPG signature. `bundle.json.ksig` is an OpenSSL RSA signature.
- pem files are listed by hash in `bundle.json`. They are not signed one by one.
- `root.pem` is stored in the clear. Every other key is encrypted with the fixed section of `root.pem` before it is hashed.

GnuPG signing keys are created with no expiry (`Expire-Date: 0` in `python/ker/sign.py`). The kernel certificate is the long-lived X.509 certificate from the same module. Trust on the medium is the signed `bundle.json` hash list.

## How a disc is produced

1. During `ker` init or a later rotation, choose a device whose kind is `dvd-r` or `optical`.
2. KER builds an ISO9660 image with `xorriso` and writes that image to the device. The image label is `KER_AUTH`. With `KER_PREFIX` set, the image path is under that prefix's `var/lib/ker/<media_id>.iso`. On a host it is `/var/lib/ker/<media_id>.iso`.
3. Do not add extra files after the image is built. Verification requires the file set to match the bundle exactly.

Optical media is not rewritten in place. Replace a lost disc with `ker revoke-medium --replace` (see the README). A package upgrade does not rewrite sealed media and does not turn kernel enforcement on.

## DVD-R 与光盘（0.1.0）

KER 可以把一套密钥封到 DVD-R 或其他光盘上。这是一张数据盘，不是可启动的系统盘，也不会安装 KER，更不会因此打开内核拦截。

盘上被签名的对象是 `bundle.json`（介质格式 2）。`expiry_policy` 为 `never`，`expires` 为 null。`bundle.json.sig` 是 GPG 分离签名，`bundle.json.ksig` 是 OpenSSL RSA 签名。pem 文件只出现在哈希清单里，没有各自的签名。`root.pem` 明文存放，其余密钥先用 `root.pem` 的固定段加密再计算哈希。

初始化或轮换时选择 `dvd-r` / `optical`。KER 用 `xorriso` 生成卷标为 `KER_AUTH` 的 ISO9660 镜像并写入设备。设置了 `KER_PREFIX` 时，镜像在该前缀下的 `var/lib/ker/<media_id>.iso`；在主机上则是 `/var/lib/ker/<media_id>.iso`。不要往镜像里追加文件，否则验签会失败。

光盘不能原地改写。丢失后用 `ker revoke-medium --replace` 更换。软件包升级不会改写已密封介质，也不会自行打开内核拦截。
