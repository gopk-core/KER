#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

/* Global flag + per-category deny when enforcement is on and media is missing.
 *
 * Critical system services stay usable so the machine does not fall apart
 * and so reinserting media can recover enforcement maps. User/workload
 * read, write and exec are still denied when the matching media are gone.
 *
 * Exec is judged by the *target* basename (the program being started), not
 * the current comm. Judging by current comm would allow every command
 * launched from bash, and would deny journald/udevd started via
 * systemd-executor.
 *
 * TASK_COMM_LEN is 16 bytes including the trailing NUL, so names longer
 * than 15 characters are matched in truncated form:
 *   systemd-journald  -> systemd-journal
 *   systemd-executor  -> systemd-executo
 *   systemd-shutdown  -> systemd-shutdow
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

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct cfg);
} cfg_map SEC(".maps");

static __always_inline int comm_eq(const char *c, const char *s)
{
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        if (c[i] != s[i])
            return 0;
        if (s[i] == 0)
            return 1;
    }
    return 1;
}

/* Keep this list in sync with ker.enforce.ALLOWED_COMMS. */
static __always_inline int is_allowed_name(const char *c)
{
    if (comm_eq(c, "systemd") ||
        comm_eq(c, "init") ||
        comm_eq(c, "systemd-journal") ||
        comm_eq(c, "systemd-udevd") ||
        comm_eq(c, "systemd-executo") ||
        comm_eq(c, "udev-worker") ||
        comm_eq(c, "systemd-udev-wo") ||
        comm_eq(c, "dbus-daemon") ||
        comm_eq(c, "dbus-broker") ||
        comm_eq(c, "dbus-broker-lau") ||
        comm_eq(c, "ker") ||
        comm_eq(c, "ker-enforcer") ||
        comm_eq(c, "ker-sync") ||
        comm_eq(c, "ker-boot-check") ||
        comm_eq(c, "ker-python") ||
        comm_eq(c, "ata_id") ||
        comm_eq(c, "scsi_id") ||
        comm_eq(c, "usb_id") ||
        comm_eq(c, "blkid") ||
        comm_eq(c, "cdrom_id") ||
        comm_eq(c, "timeout") ||
        comm_eq(c, "gpgv") ||
        comm_eq(c, "openssl") ||
        comm_eq(c, "bpftool") ||
        comm_eq(c, "mount") ||
        comm_eq(c, "umount") ||
        comm_eq(c, "udevadm") ||
        comm_eq(c, "systemctl") ||
        comm_eq(c, "reboot") ||
        comm_eq(c, "poweroff") ||
        comm_eq(c, "halt") ||
        comm_eq(c, "shutdown") ||
        comm_eq(c, "systemd-shutdow"))
        return 1;
    return 0;
}

static __always_inline int allowed_comm(void)
{
    char c[16] = {};
    bpf_get_current_comm(&c, sizeof(c));
    return is_allowed_name(c);
}

static __always_inline void basename16(char dst[16], const char *path)
{
    char tmp[16] = {};
    int sl = 0;

    #pragma unroll
    for (int i = 0; i < 127; i++) {
        char ch = path[i];
        if (ch == 0)
            break;
        if (ch == '/') {
            sl = 0;
            #pragma unroll
            for (int j = 0; j < 16; j++)
                tmp[j] = 0;
            continue;
        }
        if (sl < 15) {
            tmp[sl] = ch;
            sl++;
        }
    }
    #pragma unroll
    for (int i = 0; i < 16; i++)
        dst[i] = tmp[i];
}

static __always_inline int read_cstr(char *dst, int size, const char *src)
{
    long n;
    if (!src || size <= 0)
        return 0;
    n = bpf_probe_read_kernel_str(dst, size, src);
    if (n > 0)
        return 1;
    n = bpf_probe_read_user_str(dst, size, src);
    return n > 0;
}

static __always_inline int starts_with(const char *s, const char *pfx)
{
    #pragma unroll
    for (int i = 0; i < 24; i++) {
        if (pfx[i] == 0)
            return 1;
        if (s[i] != pfx[i])
            return 0;
    }
    return 1;
}

/* Exec allow is based on the target path/basename, never the parent comm.
 * Prefixes keep systemd and KER helpers startable without opening a general shell.
 */
static __always_inline int path_is_allowed(const char *path)
{
    /* KER helpers under /usr/lib/ker/ stay startable when media is missing,
     * except the exact path /usr/lib/ker/ker-probe, which is a user-facing
     * checker and must follow media_ok. Compare with constant offsets only;
     * a generic basename walk is too expensive for the verifier.
     */
    if (starts_with(path, "/usr/lib/ker/")) {
        const char *probe = "ker-probe";
        int match = 1;
        #pragma unroll
        for (int i = 0; i < 9; i++) {
            if (path[13 + i] != probe[i])
                match = 0;
        }
        if (match && path[22] == 0)
            return 0;
        return 1;
    }
    if (starts_with(path, "/usr/lib/systemd/") ||
        starts_with(path, "/lib/systemd/") ||
        starts_with(path, "/usr/lib/udev/") ||
        starts_with(path, "/lib/udev/") ||
        starts_with(path, "/usr/sbin/ker") ||
        starts_with(path, "/usr/bin/systemctl") ||
        starts_with(path, "/bin/systemctl") ||
        starts_with(path, "/usr/bin/udevadm") ||
        starts_with(path, "/bin/udevadm") ||
        starts_with(path, "/sbin/udevadm") ||
        starts_with(path, "/usr/sbin/udevadm") ||
        starts_with(path, "/usr/sbin/bpftool") ||
        starts_with(path, "/usr/bin/bpftool") ||
        starts_with(path, "/bin/mount") ||
        starts_with(path, "/sbin/mount") ||
        starts_with(path, "/usr/bin/mount") ||
        starts_with(path, "/usr/sbin/mount") ||
        starts_with(path, "/bin/umount") ||
        starts_with(path, "/sbin/umount") ||
        starts_with(path, "/usr/bin/umount") ||
        starts_with(path, "/usr/sbin/umount") ||
        starts_with(path, "/sbin/reboot") ||
        starts_with(path, "/usr/sbin/reboot") ||
        starts_with(path, "/sbin/poweroff") ||
        starts_with(path, "/usr/sbin/poweroff") ||
        starts_with(path, "/sbin/halt") ||
        starts_with(path, "/usr/sbin/halt") ||
        starts_with(path, "/sbin/shutdown") ||
        starts_with(path, "/usr/sbin/shutdown"))
        return 1;
    return 0;
}

static __always_inline int allowed_exec(struct linux_binprm *bprm)
{
    char path[128] = {};
    char name[16] = {};
    const char *fn;

    fn = BPF_CORE_READ(bprm, filename);
    if (read_cstr(path, sizeof(path), fn) && path_is_allowed(path))
        return 1;

    /* dentry name is already a basename (TASK_COMM_LEN-sized). */
    if (read_cstr(name, sizeof(name),
                  (const char *)BPF_CORE_READ(bprm, file, f_path.dentry, d_name.name)) &&
        is_allowed_name(name))
        return 1;

    __builtin_memset(path, 0, sizeof(path));
    fn = BPF_CORE_READ(bprm, interp);
    if (read_cstr(path, sizeof(path), fn) && path_is_allowed(path))
        return 1;
    return 0;
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
    if (mask & 0x01) /* MAY_EXEC is handled in bprm; MAY_READ=4 MAY_WRITE=2 vary */
        bits |= BIT_READ;
    if (mask & 0x02)
        bits |= BIT_WRITE;
    if (mask & 0x04)
        bits |= BIT_READ;
    if (!bits)
        bits = BIT_READ;
    return decide(bits, ret, allowed_comm());
}

SEC("lsm/file_open")
int BPF_PROG(ker_open, struct file *file, int ret)
{
    return decide(BIT_READ | BIT_WRITE, ret, allowed_comm());
}

SEC("lsm/task_fix_setuid")
int BPF_PROG(ker_setuid, struct cred *new, const struct cred *old, int flags, int ret)
{
    __u32 uid = BPF_CORE_READ(new, euid.val);
    return uid == 0 ? decide(BIT_ROOTSU, ret, allowed_comm()) : ret;
}

SEC("lsm/socket_connect")
int BPF_PROG(ker_connect, struct socket *sock, struct sockaddr *addr, int addrlen, int ret)
{
    return decide(BIT_NETWORK, ret, allowed_comm());
}

char LICENSE[] SEC("license") = "GPL";
