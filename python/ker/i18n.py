from __future__ import annotations

LANGS = {
    'en': 'English',
    'zh-CN': '简体中文',
    'zh-TW': '繁體中文',
}

_T = {
    'choose_language': {
        'en': 'Select language',
        'zh-CN': '请选择语言',
        'zh-TW': '請選擇語言',
    },
    'need_root': {
        'en': 'This command must be run as root.',
        'zh-CN': '必须使用 root 执行。',
        'zh-TW': '必須使用 root 執行。',
    },
    'confirm_wipe': {
        'en': 'This will format the selected media and erase all data. Extra files will later fail verification. Type y to continue.',
        'zh-CN': '将格式化所选介质并清空全部数据，之后不能存放额外文件，否则验签失败。输入 y 继续。',
        'zh-TW': '將格式化所選介質並清空全部資料，之後不能存放額外檔案，否則驗簽失敗。輸入 y 繼續。',
    },
    'write_once_warn': {
        'en': 'The selected media looks write-once (for example DVD-R or WORM). A special write path will be used and cannot be rewritten later. Type y to continue, n to exit.',
        'zh-CN': '所选介质类似一次性写入介质（如 DVD-R 或 WORM）。将使用特殊写入方式，之后无法改写。输入 y 继续，n 退出。',
        'zh-TW': '所選介質類似一次性寫入介質（如 DVD-R 或 WORM）。將使用特殊寫入方式，之後無法改寫。輸入 y 繼續，n 退出。',
    },
    'worm_not_empty': {
        'en': 'WORM media is not empty; refusing to continue.',
        'zh-CN': 'WORM 介质不是空的，已退出。',
        'zh-TW': 'WORM 介質不是空的，已退出。',
    },
    'test_mode_intro': {
        'en': 'Media test mode is on: verification failures are reported in the terminal only. No kernel blocking is enabled.',
        'zh-CN': '已进入介质测试模式：校验失败只在终端提示，不会启用任何内核拦截。',
        'zh-TW': '已進入介質測試模式：校驗失敗只在終端提示，不會啟用任何核心攔截。',
    },
    'replug_prompt': {
        'en': 'Unplug and reinsert this medium to confirm the keys were written: {name}',
        'zh-CN': '请拔出再插回以下介质，以确认密钥已写入成功：{name}',
        'zh-TW': '請拔出再插回以下介質，以確認金鑰已寫入成功：{name}',
    },
    'secureboot_warn': {
        'en': 'Secure Boot or kernel lockdown is missing or inactive. KER can still run, but a root user can replace the verifier or kernel. Use a machine with Secure Boot enabled for a firmware trust root.',
        'zh-CN': '未检测到已启用的 Secure Boot 或 kernel lockdown。KER 仍可运行，但已有 root 权限的人可以替换校验组件或内核。要建立固件级信任根，请换用已启用 Secure Boot 的设备。',
        'zh-TW': '未偵測到已啟用的 Secure Boot 或 kernel lockdown。KER 仍可執行，但已有 root 權限的人可以替換校驗元件或核心。要建立韌體級信任根，請改用已啟用 Secure Boot 的設備。',
    },
    'uninstall_need_media': {
        'en': 'Connect the root medium and every permission medium, then rerun ker uninstall.',
        'zh-CN': '请同时接上根介质以及全部权限密钥介质后，再执行 ker uninstall。',
        'zh-TW': '請同時接上根介質以及全部權限金鑰介質後，再執行 ker uninstall。',
    },
    'uninstall_children': {
        'en': 'These child KER nodes will also be uninstalled if they are online:\n{nodes}\nType y to continue.',
        'zh-CN': '卸载将向下列在线子 KER 下发卸载（在线才会被一起卸载）：\n{nodes}\n输入 y 继续。',
        'zh-TW': '解除安裝將向下列線上子 KER 下發解除安裝（線上才會被一起卸載）：\n{nodes}\n輸入 y 繼續。',
    },
    'addnet_intro': {
        'en': 'ker addnet will install KER into the kernel on this machine, join it to the LAN as a child node, and connect it to the main KER host. It will not create a new root key.',
        'zh-CN': 'ker addnet 会在本机把 KER 装入内核，将当前设备作为局域网中的子 KER 节点，并连接到主 KER 主机。不会在本机签发新的根密钥。',
        'zh-TW': 'ker addnet 會在本機把 KER 裝入核心，將目前設備作為區域網路中的子 KER 節點，並連線到主 KER 主機。不會在本機簽發新的根金鑰。',
    },
    'console_need_admin': {
        'en': 'Insert the dedicated admin-key medium and retry.',
        'zh-CN': '请插入单独的管理密钥介质后再试。',
        'zh-TW': '請插入單獨的管理金鑰介質後再試。',
    },
    'ok': {'en': 'OK', 'zh-CN': '完成', 'zh-TW': '完成'},
    'fail': {'en': 'FAILED', 'zh-CN': '失败', 'zh-TW': '失敗'},
    'upgrade_not_init': {
        'en': 'KER is installed but not initialized. Installing a newer package only replaces program files; run ker afterwards to set up.',
        'zh-CN': 'KER 已安装但尚未初始化。安装新包只会替换程序文件，之后再运行 ker 进行首次设置。',
        'zh-TW': 'KER 已安裝但尚未初始化。安裝新包只會替換程式檔，之後再執行 ker 進行首次設定。',
    },
    'upgrade_already': {
        'en': 'Already current: package {version}, state schema {schema}. Nothing to migrate.',
        'zh-CN': '已是当前版本：软件包 {version}，状态格式 {schema}。无需迁移。',
        'zh-TW': '已是目前版本：套件 {version}，狀態格式 {schema}。無需遷移。',
    },
    'upgrade_need_migrate': {
        'en': 'Upgrade ready: package {src} -> {dst}, state schema {from_schema} -> {to_schema}.',
        'zh-CN': '可以升级：软件包 {src} → {dst}，状态格式 {from_schema} → {to_schema}。',
        'zh-TW': '可以升級：套件 {src} → {dst}，狀態格式 {from_schema} → {to_schema}。',
    },
    'upgrade_enforcement_kept': {
        'en': 'Run mode will stay {mode}, kernel enforcement {enforcement}. Sealed media will not be rewritten.',
        'zh-CN': '运行模式保持为 {mode}，内核拦截保持 {enforcement}。不会改写已密封的介质。',
        'zh-TW': '執行模式保持為 {mode}，核心攔截保持 {enforcement}。不會改寫已密封的介質。',
    },
    'upgrade_migrations': {
        'en': 'Pending migrations: {ids}',
        'zh-CN': '待执行迁移：{ids}',
        'zh-TW': '待執行遷移：{ids}',
    },
    'upgrade_added': {
        'en': 'New features available after this package: {ids}',
        'zh-CN': '本包将提供的新功能：{ids}',
        'zh-TW': '本包將提供的新功能：{ids}',
    },
    'upgrade_replacements': {
        'en': 'Feature replacements: {ids}',
        'zh-CN': '功能替换：{ids}',
        'zh-TW': '功能替換：{ids}',
    },
    'upgrade_no_auto': {
        'en': 'KER never updates itself. Run: ker upgrade --migrate   or install the new package by hand.',
        'zh-CN': 'KER 不会自行更新。请执行：ker upgrade --migrate  或手动安装新的软件包。',
        'zh-TW': 'KER 不會自行更新。請執行：ker upgrade --migrate  或手動安裝新的套件。',
    },
    'upgrade_ok': {
        'en': 'Upgrade finished: {src} -> {dst}.',
        'zh-CN': '升级完成：{src} → {dst}。',
        'zh-TW': '升級完成：{src} → {dst}。',
    },
    'upgrade_rollback_ok': {
        'en': 'Restored the last upgrade snapshot: {path}',
        'zh-CN': '已恢复最近一次升级快照：{path}',
        'zh-TW': '已恢復最近一次升級快照：{path}',
    },
    'no_devices': {
        'en': 'No candidate media found.',
        'zh-CN': '没有找到可作为授权介质的设备。',
        'zh-TW': '沒有找到可作為授權介質的設備。',
    },
    'hook_boot_ok': {
        'en': 'KER boot authorization succeeded.',
        'zh-CN': 'KER 启动授权通过。',
        'zh-TW': 'KER 啟動授權通過。',
    },
    'hook_boot_fail': {
        'en': 'KER boot authorization failed; refusing to continue.',
        'zh-CN': 'KER 启动授权失败，拒绝继续启动。',
        'zh-TW': 'KER 啟動授權失敗，拒絕繼續啟動。',
    },
    'hook_ssh_deny': {
        'en': 'KER SSH authorization failed.',
        'zh-CN': 'KER SSH 授权失败。',
        'zh-TW': 'KER SSH 授權失敗。',
    },
}



def t(lang: str, key: str, **kwargs) -> str:
    lang = lang if lang in LANGS else 'zh-CN'
    text = _T.get(key, {}).get(lang) or _T.get(key, {}).get('en') or key
    return text.format(**kwargs) if kwargs else text
