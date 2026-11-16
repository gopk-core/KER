#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

/* Global flag + per-category deny when enforcement is on.
 *
 * media_ok == 1 means no selected runtime bit is denied because a medium
 * is missing or unverified. It does not mean decide() allows every class.
 * deny_mask lists the bits to deny when media_ok == 0. Removing one
 * permission medium denies only the bits that medium authorizes.
 * narrow_mask is policy from an active replace rule. It is applied even
 * when media_ok is 1: media_ok == 1 does not open a class that narrow_mask
 * still names. Older writers leave narrow_mask zero.
 *
 * Allowlisting is by inode+device of concrete executable paths, filled
 * from userspace (ker.enforce.ALLOWED_EXEC_PATHS) into the allow_inos
 * hash. Comm / dentry basename is not an authorization: a binary renamed
 * to systemd must not pass, and /usr/lib/ker/ as a directory is not allowed.
 *
 * Custom rules do not set a machine-wide bit. scope_inos / scope_uids /
 * scope_ports / scope_net4 / scope_net6 name the exact subject. A port
 * entry is a ports-only grant (any destination address). An address
 * constraint is a scope_net4 or scope_net6 entry and is never widened
 * into the port map.
 *
 * Linux MAY_* values (include/linux/fs.h):
 *   MAY_EXEC 0x1, MAY_WRITE 0x2, MAY_READ 0x4, MAY_APPEND 0x8.
 *
 * Never turns another LSM's denial into an allow.
 */
struct cfg {
    __u32 enforcement;
    __u32 media_ok;
    __u32 deny_mask;
    __u32 narrow_mask;
};

#define BIT_RUN      (1U << 0)
#define BIT_READ     (1U << 1)
#define BIT_WRITE    (1U << 2)
#define BIT_ROOTSU   (1U << 3)
#define BIT_NETWORK  (1U << 4)
#define BIT_ROOTUSER (1U << 5)
#define BIT_SSH      (1U << 6)

#define MAY_EXEC     0x01
#define MAY_WRITE    0x02
#define MAY_READ     0x04
#define MAY_APPEND   0x08

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct cfg);
} cfg_map SEC(".maps");

/* Hash of inode+device. Userspace inserts one entry per concrete allowed
 * path and does not rewrite unchanged keys. 16-byte key: u64 ino, u32 dev,
 * u32 pad. Value is a nonzero flag.
 */
struct allow_key {
    __u64 ino;
    __u32 dev;
    __u32 pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct allow_key);
    __type(value, __u32);
} allow_inos SEC(".maps");

struct scope_val {
    __u32 allow_bits;
    __u32 deny_bits;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct allow_key);
    __type(value, struct scope_val);
} scope_inos SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct scope_val);
} scope_uids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct scope_val);
} scope_ports SEC(".maps");

/* Address + port. Key layout is shared with ker.enforce.net4_key_bytes /
 * net6_key_bytes: address bytes in wire order, then host-order port.
 * A ports-only grant stays in scope_ports and is not written here.
 */
struct net4_key {
    __u8 addr[4];
    __u16 port;
    __u16 pad;
};

struct net6_key {
    __u8 addr[16];
    __u16 port;
    __u16 pad;
};

/* Userspace packs these exact widths. A trailing pad would desync the maps. */
_Static_assert(sizeof(struct net4_key) == 8, "net4 key size");
_Static_assert(sizeof(struct net6_key) == 20, "net6 key size");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct net4_key);
    __type(value, struct scope_val);
} scope_net4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, struct net6_key);
    __type(value, struct scope_val);
} scope_net6 SEC(".maps");

static __always_inline int ino_allowed(__u64 ino, __u32 dev)
{
    struct allow_key k = {};
    k.ino = ino;
    k.dev = dev;
    __u32 *v = bpf_map_lookup_elem(&allow_inos, &k);
    return v != NULL;
}

static __always_inline int scope_copy(struct scope_val *dst, struct scope_val *src)
{
    if (!src)
        return 0;
    dst->allow_bits = src->allow_bits;
    dst->deny_bits = src->deny_bits;
    return 1;
}

static __always_inline int scope_for_ino(__u64 ino, __u32 dev, struct scope_val *out)
{
    struct allow_key k = {};
    k.ino = ino;
    k.dev = dev;
    return scope_copy(out, bpf_map_lookup_elem(&scope_inos, &k));
}

static __always_inline int scope_for_uid(__u32 uid, struct scope_val *out)
{
    return scope_copy(out, bpf_map_lookup_elem(&scope_uids, &uid));
}

static __always_inline int scope_for_port(__u32 port, struct scope_val *out)
{
    return scope_copy(out, bpf_map_lookup_elem(&scope_ports, &port));
}

static __always_inline int scope_for_net4(struct net4_key *key, struct scope_val *out)
{
    return scope_copy(out, bpf_map_lookup_elem(&scope_net4, key));
}

static __always_inline int scope_for_net6(struct net6_key *key, struct scope_val *out)
{
    return scope_copy(out, bpf_map_lookup_elem(&scope_net6, key));
}

static __always_inline int file_identity(struct file *file, __u64 *ino, __u32 *dev)
{
    struct inode *inode;
    struct super_block *sb;

    if (!file)
        return 0;
    inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;
    sb = BPF_CORE_READ(inode, i_sb);
    if (!sb)
        return 0;
    *ino = BPF_CORE_READ(inode, i_ino);
    *dev = BPF_CORE_READ(sb, s_dev);
    return 1;
}

static __always_inline int file_allowed(struct file *file)
{
    __u64 ino = 0;
    __u32 dev = 0;

    if (!file_identity(file, &ino, &dev))
        return 0;
    return ino_allowed(ino, dev);
}

static __always_inline int file_scope(struct file *file, struct scope_val *out)
{
    __u64 ino = 0;
    __u32 dev = 0;

    if (!file_identity(file, &ino, &dev))
        return 0;
    return scope_for_ino(ino, dev, out);
}

/* Exec allow is the opened file's inode, never the dentry basename and
 * never the parent comm. A shebang records both the script inode
 * (/usr/sbin/ker) and the interpreter inode (/usr/lib/ker/ker-python),
 * so the packaging interpreter name still works without allowing python3.
 */
static __always_inline int allowed_exec(struct linux_binprm *bprm)
{
    struct file *file;

    file = BPF_CORE_READ(bprm, file);
    return file_allowed(file);
}

/* Post-exec hooks must not trust the task comm. After a renamed exec the
 * comm is the new basename. The executable inode is stable.
 */
static __always_inline int allowed_current(void)
{
    struct task_struct *task;
    struct mm_struct *mm;
    struct file *exe;

    task = (struct task_struct *)bpf_get_current_task();
    mm = BPF_CORE_READ(task, mm);
    if (!mm)
        return 0;
    exe = BPF_CORE_READ(mm, exe_file);
    return file_allowed(exe);
}

/* Global policy, then the subject scope.
 *
 * narrow_mask blocks a class unless this subject has an allow bit.
 * It is applied whether or not media_ok is set. media_ok == 1 does not
 * open a class that narrow_mask still names. deny_mask is the
 * missing-medium mask and is applied only when media_ok is 0.
 * scope deny blocks that subject even when the class is otherwise open.
 * scope allow clears only the bits it names, so a path grant cannot open
 * a different path or a different class.
 */
static __always_inline int decide_subject(__u32 bit, int ret, int allowed,
                                         struct scope_val *scope, int have_scope)
{
    __u32 blocked;
    __u32 z = 0;
    struct cfg *c;

    if (ret)
        return ret;
    if (allowed)
        return 0;
    c = bpf_map_lookup_elem(&cfg_map, &z);
    if (!c || !c->enforcement)
        return 0;
    /* Replace-rule narrow stays in force after every medium verifies. */
    blocked = c->narrow_mask & bit;
    if (!c->media_ok)
        blocked |= c->deny_mask & bit;
    if (have_scope && scope) {
        blocked |= scope->deny_bits & bit;
        blocked &= ~scope->allow_bits;
    }
    if (blocked)
        return -13; /* EACCES */
    return 0;
}

static __always_inline int decide(__u32 bit, int ret, int allowed)
{
    return decide_subject(bit, ret, allowed, 0, 0);
}

SEC("lsm/bprm_check_security")
int BPF_PROG(ker_exec, struct linux_binprm *bprm, int ret)
{
    struct scope_val file_sv = {};
    struct scope_val uid_sv = {};
    const struct cred *cred;
    int have_file;
    int have_uid;
    int allowed;
    int r;
    __u32 uid;

    allowed = allowed_exec(bprm);
    have_file = file_scope(BPF_CORE_READ(bprm, file), &file_sv);
    r = decide_subject(BIT_RUN, ret, allowed, &file_sv, have_file);
    if (r)
        return r;
    cred = BPF_CORE_READ(bprm, cred);
    uid = BPF_CORE_READ(cred, euid.val);
    /* Login scope is the root-login bit, and only for euid 0.
     * A grant for any other uid must not reach decide_subject: its
     * allow_bits would clear BIT_ROOTUSER on that uid's ordinary exec.
     * Non-root login rules are enforced by the SSH PAM helper.
     */
    if (uid != 0)
        return 0;
    have_uid = scope_for_uid(0, &uid_sv);
    return decide_subject(BIT_ROOTUSER, 0, allowed, &uid_sv, have_uid);
}

SEC("lsm/file_permission")
int BPF_PROG(ker_io, struct file *file, int mask, int ret)
{
    __u32 bits = 0;
    /* MAY_EXEC is the execute bit, the same class as bprm / BIT_RUN.
     * Combined masks (read+write, exec+read, append) keep every class.
     */
    if (mask & MAY_EXEC)
        bits |= BIT_RUN;
    if (mask & MAY_WRITE)
        bits |= BIT_WRITE;
    if (mask & MAY_READ)
        bits |= BIT_READ;
    if (mask & MAY_APPEND)
        bits |= BIT_WRITE;
    if (!bits)
        return ret;
    {
        struct scope_val sv = {};
        int have = file_scope(file, &sv);
        return decide_subject(bits, ret, allowed_current(), &sv, have);
    }
}

SEC("lsm/file_open")
int BPF_PROG(ker_open, struct file *file, int ret)
{
    struct scope_val sv = {};
    int have = file_scope(file, &sv);
    return decide_subject(BIT_READ | BIT_WRITE, ret, allowed_current(), &sv, have);
}

SEC("lsm/task_fix_setuid")
int BPF_PROG(ker_setuid, struct cred *new, const struct cred *old, int flags, int ret)
{
    struct scope_val sv = {};
    __u32 uid = BPF_CORE_READ(new, euid.val);
    int have;
    int allowed = allowed_current();
    int r;

    /* Becoming a non-root uid is not a root login and not setuid-to-root.
     * Do not apply a login scope's allow or deny bits on that path.
     */
    if (uid != 0)
        return ret;
    have = scope_for_uid(0, &sv);
    /* Privilege class, without the login scope, so a BIT_ROOTUSER grant
     * cannot clear BIT_ROOTSU.
     */
    r = decide_subject(BIT_ROOTSU, ret, allowed, 0, 0);
    if (r)
        return r;
    /* uid 0 login grant/lock is BIT_ROOTUSER. Honor it on this transition. */
    if (have && ((sv.allow_bits | sv.deny_bits) & BIT_ROOTUSER))
        return decide_subject(BIT_ROOTUSER, 0, allowed, &sv, 1);
    return 0;
}

/* AF_UNIX (1) and AF_NETLINK (16) are not port-scoped grants. They are
 * left without a scope on purpose: a TCP/UDP port allow does not cover
 * them, and they are not rewritten into one.
 */
#define KER_AF_INET  2
#define KER_AF_INET6 10

SEC("lsm/socket_connect")
int BPF_PROG(ker_connect, struct socket *sock, struct sockaddr *addr, int addrlen, int ret)
{
    struct scope_val sv = {};
    int have = 0;
    __u16 family = 0;

    if (addr && addrlen > 0) {
        family = BPF_CORE_READ(addr, sa_family);
        /* connect() is outbound. An exact address+port entry is preferred
         * over a ports-only entry so a grant for one address is not an
         * allow for every address on that port. A ports-only map entry
         * still matches any destination, because that rule named no
         * address. Inbound is not mediated here.
         */
        if (family == KER_AF_INET && addrlen >= (int)sizeof(struct sockaddr_in)) {
            struct sockaddr_in in4 = {};
            struct net4_key key = {};
            __u32 port;

            bpf_core_read(&in4, sizeof(in4), addr);
            key.port = bpf_ntohs(in4.sin_port);
            __builtin_memcpy(key.addr, &in4.sin_addr.s_addr, 4);
            have = scope_for_net4(&key, &sv);
            if (!have) {
                port = key.port;
                have = scope_for_port(port, &sv);
            }
        } else if (family == KER_AF_INET6 && addrlen >= (int)sizeof(struct sockaddr_in6)) {
            struct sockaddr_in6 in6 = {};
            struct net6_key key = {};
            __u32 port;

            bpf_core_read(&in6, sizeof(in6), addr);
            key.port = bpf_ntohs(in6.sin6_port);
            __builtin_memcpy(key.addr, in6.sin6_addr.in6_u.u6_addr8, 16);
            have = scope_for_net6(&key, &sv);
            if (!have) {
                port = key.port;
                have = scope_for_port(port, &sv);
            }
        }
    }
    return decide_subject(BIT_NETWORK, ret, allowed_current(), &sv, have);
}

char LICENSE[] SEC("license") = "GPL";
