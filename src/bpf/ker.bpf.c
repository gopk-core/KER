#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

/* Global flag + per-category deny when enforcement is on.
 *
 * media_ok == 1 means no runtime permission bit is currently denied.
 * deny_mask lists the bits to deny when media_ok == 0. Removing one
 * permission medium denies only the bits that medium authorizes.
 *
 * Allowlisting is by inode+device of concrete executable paths, filled
 * from userspace (ker.enforce.ALLOWED_EXEC_PATHS) into allow_inos.
 * Comm / dentry basename is not an authorization: a binary renamed to
 * systemd must not pass, and /usr/lib/ker/ as a directory is not allowed.
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
    __u32 reserved;
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

/* One slot per concrete allowed path. used=0 slots are ignored.
 * Userspace rewrites every slot whenever maps are updated.
 */
struct ino_slot {
    __u64 ino;
    __u32 dev;
    __u32 used;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, struct ino_slot);
} allow_inos SEC(".maps");

static __always_inline int ino_allowed(__u64 ino, __u32 dev)
{
    #pragma unroll
    for (int i = 0; i < 64; i++) {
        __u32 k = i;
        struct ino_slot *s = bpf_map_lookup_elem(&allow_inos, &k);
        if (!s || !s->used)
            continue;
        if (s->ino == ino && s->dev == dev)
            return 1;
    }
    return 0;
}

static __always_inline int file_allowed(struct file *file)
{
    struct inode *inode;
    struct super_block *sb;
    __u64 ino;
    __u32 dev;

    if (!file)
        return 0;
    inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;
    sb = BPF_CORE_READ(inode, i_sb);
    if (!sb)
        return 0;
    ino = BPF_CORE_READ(inode, i_ino);
    dev = BPF_CORE_READ(sb, s_dev);
    return ino_allowed(ino, dev);
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

static __always_inline int decide(__u32 bit, int ret, int allowed)
{
    if (ret)
        return ret;
    if (allowed)
        return 0;
    __u32 z = 0;
    struct cfg *c = bpf_map_lookup_elem(&cfg_map, &z);
    if (!c || !c->enforcement)
        return 0;
    if (c->media_ok)
        return 0;
    if (c->deny_mask & bit)
        return -13; /* EACCES */
    return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(ker_exec, struct linux_binprm *bprm, int ret)
{
    int r = decide(BIT_RUN, ret, allowed_exec(bprm));
    if (r)
        return r;
    const struct cred *cred = BPF_CORE_READ(bprm, cred);
    __u32 uid = BPF_CORE_READ(cred, euid.val);
    return uid == 0 ? decide(BIT_ROOTUSER, 0, allowed_exec(bprm)) : 0;
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
    return decide(bits, ret, allowed_current());
}

SEC("lsm/file_open")
int BPF_PROG(ker_open, struct file *file, int ret)
{
    return decide(BIT_READ | BIT_WRITE, ret, allowed_current());
}

SEC("lsm/task_fix_setuid")
int BPF_PROG(ker_setuid, struct cred *new, const struct cred *old, int flags, int ret)
{
    __u32 uid = BPF_CORE_READ(new, euid.val);
    return uid == 0 ? decide(BIT_ROOTSU, ret, allowed_current()) : ret;
}

SEC("lsm/socket_connect")
int BPF_PROG(ker_connect, struct socket *sock, struct sockaddr *addr, int addrlen, int ret)
{
    return decide(BIT_NETWORK, ret, allowed_current());
}

char LICENSE[] SEC("license") = "GPL";
