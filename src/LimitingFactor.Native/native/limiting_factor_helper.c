#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/mount.h>
#include <linux/seccomp.h>
#include <linux/securebits.h>
#include <stddef.h>
#include <unistd.h>

static void fail(const char *message)
{
    fprintf(stderr, "limiting-factor-helper: %s: %s\n", message, strerror(errno));
    exit(125);
}

static void fail_value(const char *message, const char *value)
{
    fprintf(stderr, "limiting-factor-helper: %s '%s': %s\n", message, value, strerror(errno));
    exit(125);
}

static void write_all(int fd, const char *text)
{
    size_t remaining = strlen(text);
    while (remaining > 0) {
        ssize_t written = write(fd, text, remaining);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            fail("write namespace mapping");
        }
        text += written;
        remaining -= (size_t)written;
    }
}

static void write_mapping(const char *path, unsigned int inside, unsigned int outside)
{
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        fail_value("open", path);

    char mapping[96];
    int length = snprintf(mapping, sizeof(mapping), "%u %u 1\n", inside, outside);
    if (length < 0 || (size_t)length >= sizeof(mapping)) {
        close(fd);
        errno = EOVERFLOW;
        fail("format namespace mapping");
    }

    write_all(fd, mapping);
    if (close(fd) < 0)
        fail_value("close", path);
}

static void configure_user_namespace(uid_t uid, gid_t gid)
{
    if (unshare(CLONE_NEWUSER) < 0)
        fail("unshare user namespace");

    int setgroups = open("/proc/self/setgroups", O_WRONLY | O_CLOEXEC);
    if (setgroups >= 0) {
        write_all(setgroups, "deny\n");
        if (close(setgroups) < 0)
            fail("close setgroups");
    } else if (errno != ENOENT) {
        fail("open setgroups");
    }

    write_mapping("/proc/self/uid_map", 0, (unsigned int)uid);
    write_mapping("/proc/self/gid_map", 0, (unsigned int)gid);

    if (setresgid(0, 0, 0) < 0 || setresuid(0, 0, 0) < 0)
        fail("enter mapped identity");
}

static void make_mounts_private(void)
{
    if (unshare(CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS) < 0)
        fail("unshare sandbox namespaces");

    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0)
        fail("make mount namespace private");
}

static void mount_root_read_only(void)
{
    if (mount("/", "/", NULL, MS_BIND | MS_REC, NULL) < 0)
        fail("bind root filesystem");

    struct mount_attr attributes = {
        .attr_set = MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID,
    };
    if (mount_setattr(AT_FDCWD, "/", AT_RECURSIVE, &attributes, sizeof(attributes)) < 0)
        fail("make root filesystem read-only");
}

static void make_host_mounts_nodev(void)
{
    struct mount_attr attributes = { .attr_set = MOUNT_ATTR_NODEV };
    if (mount_setattr(AT_FDCWD, "/", AT_RECURSIVE, &attributes, sizeof(attributes)) < 0)
        fail("disable host devices");
}

struct device_binding {
    const char *name;
    int descriptor;
};

static void mount_private_devices(void)
{
    struct device_binding devices[] = {
        { "null", -1 },
        { "zero", -1 },
        { "full", -1 },
        { "random", -1 },
        { "urandom", -1 },
        { "tty", -1 },
    };
    size_t device_count = sizeof(devices) / sizeof(devices[0]);

    for (size_t i = 0; i < device_count; i++) {
        char source[64];
        int length = snprintf(source, sizeof(source), "/dev/%s", devices[i].name);
        if (length < 0 || (size_t)length >= sizeof(source)) {
            errno = EOVERFLOW;
            fail("format device path");
        }
        devices[i].descriptor = open(source, O_PATH | O_CLOEXEC);
        if (devices[i].descriptor < 0)
            fail_value("open device", source);
    }

    if (mount("tmpfs", "/dev", "tmpfs", MS_NOSUID | MS_NOEXEC,
            "mode=755,size=64k") < 0)
        fail("mount private /dev");

    for (size_t i = 0; i < device_count; i++) {
        char destination[64];
        char source[64];
        int destination_length = snprintf(
            destination, sizeof(destination), "/dev/%s", devices[i].name);
        int source_length = snprintf(
            source, sizeof(source), "/proc/self/fd/%d", devices[i].descriptor);
        if (destination_length < 0 || (size_t)destination_length >= sizeof(destination)
            || source_length < 0 || (size_t)source_length >= sizeof(source)) {
            errno = EOVERFLOW;
            fail("format private device path");
        }

        int target = open(destination, O_CREAT | O_CLOEXEC | O_WRONLY, 0666);
        if (target < 0)
            fail_value("create private device target", destination);
        if (close(target) < 0)
            fail_value("close private device target", destination);
        if (mount(source, destination, NULL, MS_BIND, NULL) < 0)
            fail_value("bind private device", destination);

        struct mount_attr attributes = {
            .attr_set = MOUNT_ATTR_NOSUID | MOUNT_ATTR_NOEXEC,
            .attr_clr = MOUNT_ATTR_NODEV,
        };
        if (mount_setattr(AT_FDCWD, destination, 0, &attributes, sizeof(attributes)) < 0)
            fail_value("enable private device", destination);
        if (close(devices[i].descriptor) < 0)
            fail_value("close private device", destination);
    }

    if (symlink("/proc/self/fd", "/dev/fd") < 0
        || symlink("/proc/self/fd/0", "/dev/stdin") < 0
        || symlink("/proc/self/fd/1", "/dev/stdout") < 0
        || symlink("/proc/self/fd/2", "/dev/stderr") < 0)
        fail("create private device links");
}

static void bind_mount(const char *source, const char *destination, bool read_only)
{
    if (mount(source, destination, NULL, MS_BIND | MS_REC, NULL) < 0)
        fail_value("bind mount", destination);

    struct mount_attr attributes = {
        .attr_set = MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV,
    };
    if (read_only)
        attributes.attr_set |= MOUNT_ATTR_RDONLY;
    else
        attributes.attr_clr = MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV;
    if (mount_setattr(AT_FDCWD, destination, AT_RECURSIVE, &attributes, sizeof(attributes)) < 0)
        fail_value(read_only ? "make mount tree read-only" : "make mount tree writable", destination);
}

static void mount_overlay(const char *source, const char *lower, const char *upper, const char *work)
{
    char *state = strdup(lower);
    if (state == NULL)
        fail("allocate overlay state path");
    char *separator = strrchr(state, '/');
    if (separator == NULL || separator == state) {
        free(state);
        errno = EINVAL;
        fail_value("invalid overlay state path", lower);
    }
    *separator = '\0';

    bind_mount(state, state, false);
    bind_mount(source, lower, false);
    bind_mount(source, source, false);

    size_t length = strlen(lower) + strlen(upper) + strlen(work) + 160;
    char *options = malloc(length);
    if (options == NULL)
        fail("allocate overlay options");

    int written = snprintf(
        options,
        length,
        "lowerdir=%s,upperdir=%s,workdir=%s,userxattr,index=off,metacopy=off,redirect_dir=off",
        lower,
        upper,
        work);
    if (written < 0 || (size_t)written >= length) {
        free(options);
        errno = EOVERFLOW;
        fail("format overlay options");
    }

    if (mount("overlay", source, "overlay", MS_NOSUID, options) < 0) {
        free(options);
        fail_value("mount overlay", source);
    }

    if (mount("tmpfs", state, "tmpfs", MS_NOSUID | MS_NOEXEC | MS_NODEV,
            "mode=000,size=4k") < 0) {
        free(options);
        fail_value("hide overlay state", state);
    }

    free(state);
    free(options);
}

static void mount_private_proc(void)
{
    if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL) < 0)
        fail("mount private /proc");
}

static int connect_control(const char *path)
{
    int socket_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (socket_fd < 0)
        fail("create control socket");

    struct sockaddr_un address = { .sun_family = AF_UNIX };
    if (strlen(path) >= sizeof(address.sun_path)) {
        close(socket_fd);
        errno = ENAMETOOLONG;
        fail_value("control socket path is too long", path);
    }
    strcpy(address.sun_path, path);

    if (connect(socket_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        close(socket_fd);
        fail_value("connect control socket", path);
    }

    return socket_fd;
}

static void send_fuse_fd(int control_fd, int tag, int fuse_fd)
{
    struct iovec io = { .iov_base = &tag, .iov_len = sizeof(tag) };
    char control[CMSG_SPACE(sizeof(int))] = {0};
    struct msghdr message = {
        .msg_iov = &io,
        .msg_iovlen = 1,
        .msg_control = control,
        .msg_controllen = sizeof(control),
    };
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &fuse_fd, sizeof(fuse_fd));

    for (;;) {
        if (sendmsg(control_fd, &message, MSG_NOSIGNAL) >= 0)
            return;
        if (errno != EINTR)
            fail("send FUSE descriptor");
    }
}

static void mount_approval_root(int control_fd, int tag, const char *path)
{
    int fuse_fd = open("/dev/fuse", O_RDWR | O_CLOEXEC);
    if (fuse_fd < 0)
        fail("open /dev/fuse");

    char options[160];
    int length = snprintf(options, sizeof(options),
        "fd=%d,rootmode=40000,user_id=0,group_id=0,default_permissions,allow_other", fuse_fd);
    if (length < 0 || (size_t)length >= sizeof(options)) {
        close(fuse_fd);
        errno = EOVERFLOW;
        fail("format FUSE mount options");
    }

    if (mount("limiting-factor", path, "fuse.limiting-factor",
            MS_NOSUID | MS_NODEV, options) < 0) {
        close(fuse_fd);
        fail_value("mount approval filesystem", path);
    }

    send_fuse_fd(control_fd, tag, fuse_fd);
    if (close(fuse_fd) < 0)
        fail("close transferred FUSE descriptor");
}

static void wait_for_daemons(int control_fd)
{
    char ready;
    for (;;) {
        ssize_t count = read(control_fd, &ready, 1);
        if (count == 1 && ready == 1)
            return;
        if (count < 0 && errno == EINTR)
            continue;
        if (count == 0)
            errno = ECONNRESET;
        fail("wait for FUSE daemons");
    }
}

static int parse_count(const char *value, const char *name)
{
    char *end = NULL;
    errno = 0;
    long count = strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || count < 0 || count > 4096) {
        fprintf(stderr, "limiting-factor-helper: invalid %s '%s'\n", name, value);
        exit(125);
    }
    return (int)count;
}

static void require_arguments(int index, int count, int argc, const char *option)
{
    if (index + count > argc) {
        fprintf(stderr, "limiting-factor-helper: missing values for %s\n", option);
        exit(125);
    }
}

static void drop_command_privileges(void)
{
    if (prctl(PR_SET_SECUREBITS,
            SECBIT_NOROOT | SECBIT_NOROOT_LOCKED
            | SECBIT_NO_SETUID_FIXUP | SECBIT_NO_SETUID_FIXUP_LOCKED
            | SECBIT_KEEP_CAPS_LOCKED) < 0)
        fail("lock command securebits");

    for (int capability = 0; capability < 64; capability++) {
        if (prctl(PR_CAPBSET_DROP, capability, 0, 0, 0) < 0 && errno != EINVAL)
            fail("drop command capability bounding set");
    }

    struct __user_cap_header_struct header = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0,
    };
    struct __user_cap_data_struct data[2] = {0};
    if (syscall(SYS_capset, &header, data) < 0)
        fail("clear command capabilities");
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) < 0)
        fail("clear command ambient capabilities");
}

#define DENY_SYSCALL(number, error) \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (number), 0, 1), \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (error))

static void restrict_command_syscalls(void)
{
    const unsigned int namespace_flags =
        CLONE_NEWCGROUP | CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWNS
        | CLONE_NEWPID | CLONE_NEWTIME | CLONE_NEWUSER | CLONE_NEWUTS;
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        DENY_SYSCALL(SYS_mount, EPERM),
        DENY_SYSCALL(SYS_umount2, EPERM),
        DENY_SYSCALL(SYS_pivot_root, EPERM),
        DENY_SYSCALL(SYS_chroot, EPERM),
        DENY_SYSCALL(SYS_setns, EPERM),
        DENY_SYSCALL(SYS_unshare, EPERM),
        DENY_SYSCALL(SYS_ptrace, EPERM),
#ifdef SYS_open_tree
        DENY_SYSCALL(SYS_open_tree, EPERM),
#endif
#ifdef SYS_move_mount
        DENY_SYSCALL(SYS_move_mount, EPERM),
#endif
#ifdef SYS_fsopen
        DENY_SYSCALL(SYS_fsopen, EPERM),
#endif
#ifdef SYS_fsconfig
        DENY_SYSCALL(SYS_fsconfig, EPERM),
#endif
#ifdef SYS_fsmount
        DENY_SYSCALL(SYS_fsmount, EPERM),
#endif
#ifdef SYS_mount_setattr
        DENY_SYSCALL(SYS_mount_setattr, EPERM),
#endif
#ifdef SYS_io_uring_setup
        DENY_SYSCALL(SYS_io_uring_setup, EPERM),
#endif
#ifdef SYS_clone3
        DENY_SYSCALL(SYS_clone3, ENOSYS),
#endif
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, namespace_flags, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) < 0)
        fail("install command seccomp filter");
}

static int wait_status(pid_t child)
{
    int status;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR)
            fail("wait for sandbox process");
    }
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    if (WIFSIGNALED(status))
        return 128 + WTERMSIG(status);
    return 125;
}

static int supervise_pid_namespace(char **command)
{
    pid_t namespace_init = fork();
    if (namespace_init < 0)
        fail("fork PID namespace init");

    if (namespace_init != 0)
        return wait_status(namespace_init);

    if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0)
        fail("set PID namespace parent-death signal");

    mount_private_proc();

    pid_t command_pid = fork();
    if (command_pid < 0)
        fail("fork sandbox command");
    if (command_pid == 0) {
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
            fail("set command no-new-privileges");
        drop_command_privileges();
        restrict_command_syscalls();
        execvp(command[0], command);
        fail_value("exec", command[0]);
    }

    int command_status = 125 << 8;
    bool command_exited = false;
    for (;;) {
        int status;
        pid_t reaped = waitpid(-1, &status, 0);
        if (reaped < 0) {
            if (errno == EINTR)
                continue;
            if (errno == ECHILD)
                break;
            fail("reap sandbox process");
        }
        if (reaped == command_pid) {
            command_status = status;
            command_exited = true;
            if (kill(-1, SIGKILL) < 0 && errno != ESRCH)
                fail("terminate sandbox descendants");
        } else if (!command_exited) {
            continue;
        }
    }

    if (WIFEXITED(command_status))
        _exit(WEXITSTATUS(command_status));
    if (WIFSIGNALED(command_status))
        _exit(128 + WTERMSIG(command_status));
    _exit(125);
}

int main(int argc, char **argv)
{
    uid_t host_uid = getuid();
    gid_t host_gid = getgid();
    const char *working_directory = NULL;
    int control_fd = -1;
    int approval_tag = 0;
    int index = 1;

    if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0)
        fail("set parent-death signal");

    configure_user_namespace(host_uid, host_gid);
    make_mounts_private();

    mount_root_read_only();

    if (argc == 2 && strcmp(argv[1], "--probe") == 0)
        return 0;

    while (index < argc) {
        const char *option = argv[index++];
        if (strcmp(option, "--control") == 0) {
            require_arguments(index, 1, argc, option);
            control_fd = connect_control(argv[index++]);
        } else if (strcmp(option, "--approval") == 0) {
            require_arguments(index, 1, argc, option);
            if (control_fd < 0) {
                fprintf(stderr, "limiting-factor-helper: --control must precede --approval\n");
                return 125;
            }
            mount_approval_root(control_fd, approval_tag++, argv[index++]);
        } else if (strcmp(option, "--rw") == 0) {
            require_arguments(index, 1, argc, option);
            bind_mount(argv[index], argv[index], false);
            index += 1;
        } else if (strcmp(option, "--gateway") == 0) {
            require_arguments(index, 2, argc, option);
            bind_mount(argv[index], argv[index + 1], false);
            index += 2;
        } else if (strcmp(option, "--overlay") == 0) {
            require_arguments(index, 4, argc, option);
            mount_overlay(argv[index], argv[index + 1], argv[index + 2], argv[index + 3]);
            index += 4;
        } else if (strcmp(option, "--chdir") == 0) {
            require_arguments(index, 1, argc, option);
            working_directory = argv[index++];
        } else if (strcmp(option, "--") == 0) {
            break;
        } else if (strcmp(option, "--count") == 0) {
            require_arguments(index, 1, argc, option);
            (void)parse_count(argv[index++], "count");
        } else {
            fprintf(stderr, "limiting-factor-helper: unknown option '%s'\n", option);
            return 125;
        }
    }

    if (working_directory == NULL || index >= argc) {
        fprintf(stderr, "limiting-factor-helper: --chdir and a command are required\n");
        return 125;
    }

    if (control_fd >= 0) {
        wait_for_daemons(control_fd);
        close(control_fd);
    }

    make_host_mounts_nodev();
    mount_private_devices();

    if (chdir(working_directory) < 0)
        fail_value("chdir", working_directory);

    if (unshare(CLONE_NEWPID) < 0)
        fail("unshare PID namespace");

    return supervise_pid_namespace(&argv[index]);
}
