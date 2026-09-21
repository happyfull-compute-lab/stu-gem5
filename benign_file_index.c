#define _DEFAULT_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static uint64_t checksum;
static unsigned long files, dirs, bytes;

static void visit(const char *path, int depth)
{
    struct stat st;
    if (lstat(path, &st) != 0)
        return;
    if (S_ISREG(st.st_mode)) {
        char buf[4096];
        int fd = open(path, O_RDONLY);
        if (fd < 0)
            return;
        ssize_t n = read(fd, buf, sizeof(buf));
        close(fd);
        if (n > 0) {
            for (ssize_t i = 0; i < n; ++i)
                checksum = (checksum ^ (unsigned char)buf[i]) *
                           0x100000001b3ULL;
            bytes += (unsigned long)n;
        }
        ++files;
        return;
    }
    if (!S_ISDIR(st.st_mode) || depth > 2)
        return;
    DIR *dir = opendir(path);
    if (!dir)
        return;
    ++dirs;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        char child[4096];
        int written = snprintf(child, sizeof(child), "%s/%s", path,
                               entry->d_name);
        if (written > 0 && (size_t)written < sizeof(child))
            visit(child, depth + 1);
    }
    closedir(dir);
}

int main(int argc, char **argv)
{
    const char *root = argc > 1 ? argv[1] : "/usr/include";
    checksum = 0xcbf29ce484222325ULL;
    visit(root, 0);
    printf("[FILEINDEX] root=%s dirs=%lu files=%lu bytes=%lu checksum=%llu\n",
           root, dirs, files, bytes, (unsigned long long)checksum);
    return 0;
}
