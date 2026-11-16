/* Small binary whose comm is ker-probe; used to test LSM denial. */
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int main(void) {
    int fd = open("/etc/hostname", O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    char buf[64];
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);
    if (n < 0) {
        perror("read");
        return 1;
    }
    return 0;
}
