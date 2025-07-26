/**
 * decrypter.c - IPC decrypter logic using named pipes
 * Sends subscription to encrypter and waits for encrypted password
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <time.h>
#include "mta_crypt.h"
#include "mta_rand.h"

#define ENCRYPTER_PIPE "/mnt/mta/encrypter_pipe"
#define DECRYPTER_PIPE_TEMPLATE "/mnt/mta/decrypter_pipe_%d"
#define MAX_PASSWORD_LEN 256
#define MAX_KEY_LEN 64

void print_readable_string(const char* data, int length);

int main(int argc, char* argv[]) {
    int id = getpid();  // use PID to generate unique pipe name
    char decrypter_pipe[128];
    snprintf(decrypter_pipe, sizeof(decrypter_pipe), DECRYPTER_PIPE_TEMPLATE, id);

    mkfifo(decrypter_pipe, 0666);

    // Send pipe name to encrypter
    int fd = open(ENCRYPTER_PIPE, O_WRONLY);
    if (fd < 0) {
        perror("open encrypter pipe");
        return 1;
    }

    write(fd, decrypter_pipe, strlen(decrypter_pipe));
    close(fd);

    // Wait for encrypted password
    fd = open(decrypter_pipe, O_RDONLY);
    if (fd < 0) {
        perror("open self pipe");
        return 1;
    }

    char encrypted[MAX_PASSWORD_LEN];
    memset(encrypted, 0, sizeof(encrypted));
    read(fd, encrypted, sizeof(encrypted));
    close(fd);

    printf("Decrypter %d received encrypted data.\n", id);
    print_readable_string(encrypted, MAX_PASSWORD_LEN);

    unlink(decrypter_pipe);
    return 0;
}
