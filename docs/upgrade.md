# KER 升级契约

KER 是长期稳定、不自动更新的系统。新版本只能由管理员手动安装。新包必须能接替旧包：密钥、介质、策略和运行模式继续有效，再按需迁入新功能或替换旧功能。

## 原则

- 不检查、不下载、不安装更新。没有定时任务，也没有联网升级通道。
- 新包只替换程序文件，不得删除 `/etc/ker`、`/var/lib/ker` 里的状态、信任锚和私钥。卸载软件包（非 purge 后的 `ker uninstall`）同样不得清密钥。
- 升级不得改写已密封介质，不得改变测试/强制模式，不得自行打开内核拦截。
- 状态迁移必须是单调、幂等、可跨版本跳跃的：每个包都带上从最早受支持格式到当前格式的全部迁移。
- 迁移前先做快照；失败则恢复快照。快照只覆盖主机上的状态和信任材料，不含可移动介质。
- 新功能随新包立即出现在功能目录中。需要新密钥的功能只标记为“可提供、尚未签发”，必须由管理员后续签发，不能在升级时改写已有介质。
- 被替换的旧功能若可无损映射（例如只是标识更名），迁移时自动改写；否则保留旧标识并记录替换关系，由兼容层继续识别，直到管理员明确切换。
- 禁止把当前状态格式更新到本包无法理解的新包之后再安装更旧的包（默认拒绝降级）。
- 主节点在格式或功能变化后应标记子节点需要同步；完整集群协议仍按既有设计演进，但升级框架会写下 `compat.needs_child_sync`。

## 版本轴（不要混用一个数字）

| 字段 | 含义 | 当前 |
| --- | --- | --- |
| `package_version` | 软件包语义化版本 | 0.3.0 |
| `state_schema` | 主机 `state.json` 格式，单调整数 | 1 |
| `media_schema` | 介质 `bundle.json` 格式 | 2 |
| `crypto_epoch` | 密钥封装与签名算法世代 | 1 |

本包必须能**读** `supported_media_schemas` 与 `supported_crypto_epochs` 中列出的全部历史格式。若将来更换算法，新世代要能解密旧世代；默认仍按旧格式写入，只有轮换或明确迁移才会改写介质。

清单由代码生成，安装后位于 `/usr/lib/ker/upgrade-manifest.json`。

## 管理员怎么升级

把软件包拷到目标机器（离线即可）：

```
dpkg -i ker_0.3.0_all.deb
```

或：

```
ker upgrade --trust-package ./ker_0.3.0_all.deb
```

`--trust-package` 用于尚未配置发行签名的本地包。若同时存在 `文件.sig` 和信任锚 `/etc/ker/trust/release.gpg`（或软件包附带的 `release-keys/release.gpg`），则按分离签名校验，不必再加该选项。

只检查、不改动：

```
ker upgrade
ker upgrade --check
```

已换程序文件、只补做状态迁移：

```
ker upgrade --migrate
```

恢复最近一次升级快照：

```
ker upgrade --rollback
```

Debian 维护脚本会在解包前做一次 shell 快照（即使旧包还没有 `ker upgrade`），并在 `postinst` 里调用迁移。`prerm`/`postrm` 不会删除密钥；`purge` 也只提示，不自动擦除。

## 给后续版本：新增迁移

1. 在 `python/ker/migrations/` 增加 `m0002_简述.py`，定义 `ID`、`TARGET_SCHEMA`（下一个整数）、幂等的 `apply(st, ctx)` 和 `verify(st, ctx)`。
2. 把它追加到 `python/ker/migrations/__init__.py` 的 `REGISTRY`（不得改已发布项的编号或删除它们）。
3. 把 `python/ker/compat.py` 里的 `STATE_SCHEMA` 调整为新值。若不再支持极旧来源，只允许提高 `MIN_STATE_SCHEMA` / `MIN_UPGRADE_FROM_PACKAGE`，并确认字段里已没有那些版本。
4. 补充 `tests/test_upgrade.py`：从旧状态一次性跳到新格式、再跑一遍迁移是空操作、失败时回滚。
5. 提高 `python/ker/__version__`。不要改写已有迁移。

`apply` 只应修改主机状态（以及明确属于新格式、且可安全替换的主机文件）。默认不要格式化或重签介质。

## 给后续版本：新增功能或替换旧功能

在 `python/ker/features.py` 登记功能，填写 `since_schema`、`provision_needed`（是否需要新的 pem）等。

替换旧功能时增加一条 `Feature(..., status='replaced', replaced_by='新id', lossless=True/False)`：

- `lossless=True`：迁移时把状态里的旧标识改成新标识，并记入 `feature_replacements`。
- `lossless=False`：只记录替换关系，旧标识继续工作，直到管理员完成需要的补签或策略改写。

需要新密钥的功能不得在升级时自动生成并写入旧介质。

## 升级不得做的事

- 打开或关闭内核拦截，或把测试模式改成强制模式
- 为了“跟上新格式”而重写、重签已密封介质
- 在 `prerm`/`postrm`/`purge` 里删除密钥或状态
- 自动联网检查版本
- 覆盖 `root.pem` 或权限密钥
- 在无法快照时继续改写已初始化主机的状态


## 0.1

0.1 is the first public release. It does not bump `state_schema` or
`media_schema`. An upgrade never turns kernel enforcement on or off, and
never rewrites sealed media.

This release includes architecture-specific packages (`.deb` / `.rpm` /
`.apk` / `.pkg.tar.zst`), `boot.pem` early-boot hooks, SSH hooks, and a
deny-first media presence watcher (`ker enforce --watch`). If
`state.json` already has `kernel_enforcement` enabled, a reboot restores
and attaches BPF automatically via `ker-enforcer.service`. A host that
never opted in still will not get enforcement. The fail-closed `boot.pem`
early-boot policy is unchanged.

Packages are architecture-specific, for example `ker_0.1_amd64.deb`.
Unsigned files still require `ker upgrade --trust-package`. See
`docs/hooks.md` and `docs/packaging.md`.
