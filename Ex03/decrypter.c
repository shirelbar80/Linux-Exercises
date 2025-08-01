/**
 * decrypter.c - IPC decrypter logic using named pipes
 * Sends subscription to encrypter and waits for encrypted password
 */

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <time.h>
#include <stdbool.h>
#include "mta_crypt.h"
#include "mta_rand.h"

#define ENCRYPTER_PIPE "/mnt/mta/encrypter_pipe"
#define DECRYPTER_PIPE_TEMPLATE "/mnt/mta/decrypter_pipe_%d"
#define MAX_PASSWORD_LEN 256
#define MAX_KEY_LEN 64
#define BASE_DIR "/mnt/mta"
#define PIPE_PREFIX "decrypter_pipe_"
#define CONFIG_FILE "/mnt/mta/conf.txt"



typedef struct {
    int id;
    char data[MAX_PASSWORD_LEN];
    bool isPassword;
} MsgFromDecrypter;

void print_readable_string(const char* data, int length);
int get_next_available_id();
bool decrypt_password(const char* encrypted_password, unsigned int encrypted_length, const char* key, char* decrypted_output);


int main(int argc, char* argv[]) {
   
    int password_length = 0;

    // Read password length from config
    FILE* config = fopen(CONFIG_FILE, "r");
    if (!config || fscanf(config, "%d", &password_length) != 1 || password_length <= 0) {
        perror("Failed to read config");
        exit(EXIT_FAILURE);
    }
    fclose(config);



    char* trial_key = (char*)malloc(sizeof(char) * (password_length / 8));
    char decrypter_pipe[128];
    int id = get_next_available_id();
    snprintf(decrypter_pipe, sizeof(decrypter_pipe), DECRYPTER_PIPE_TEMPLATE, id);

    mkfifo(decrypter_pipe, 0666);

    int fd_decrypter = open(decrypter_pipe, O_RDONLY | O_NONBLOCK);//open decrypter pipe to read
    if (fd_decrypter < 0) {
        perror("open self pipe");
        return 1;
    }

    //open encrypter pipe to write
    int fd_encrypter = open(ENCRYPTER_PIPE, O_WRONLY);
    if (fd_encrypter < 0) {
        perror("open encrypter pipe");
        return 1;
    }

    // Send subscription message to encrypter
    MsgFromDecrypter msg;
    msg.id = id;
    msg.isPassword = false;
    write(fd_encrypter, &msg, sizeof(msg));
       

    char current_encrypted[MAX_PASSWORD_LEN]= {0};

    while (true) {

        //tries to read a new password from the encrypter pipe:
        //if doesnt read anything countinues as usual and else updates current_encrypted
        ssize_t read_flag = read(fd_decrypter, current_encrypted, sizeof(current_encrypted));
      
        generate_random_key(trial_key, password_length / 8);

        if(decrypt_password(current_encrypted, password_length, trial_key, msg.data)){//generating a new guess

            msg.id = id;
            msg.isPassword = true;

            write(fd_encrypter, &msg, sizeof(msg));


        }

    }

    
   
    close(fd_decrypter);

    
    unlink(decrypter_pipe);
    return 0;
}




int get_next_available_id() {
    DIR *dir;
    struct dirent *entry;
    bool id_used[100] = { false }; // נניח עד 100 מפענחים

    dir = opendir(BASE_DIR);
    if (!dir) {
        perror("Failed to open /mnt/mta");
        exit(EXIT_FAILURE);
    }

    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, PIPE_PREFIX, strlen(PIPE_PREFIX)) == 0) {
            int id = atoi(entry->d_name + strlen(PIPE_PREFIX));
            if (id > 0 && id < 100) {
                id_used[id] = true;
            }
        }
    }
    closedir(dir);

    for (int i = 1; i < 100; i++) {
        if (!id_used[i]) {
            return i;
        }
    }

    fprintf(stderr, "No available decrypter IDs\n");
    exit(EXIT_FAILURE);
}


bool decrypt_password(const char* encrypted_password, unsigned int encrypted_length, const char* key, char* decrypted_output) {
   
    // Perform the decryption
    MTA_CRYPT_RET_STATUS result = MTA_decrypt((char*)key, encrypted_length/8, (char*)encrypted_password, encrypted_length, decrypted_output, &password_length);
    if (!is_printable_data(decrypted_output, password_length)) {//checks if the decrypted data is printable
        return false;
    }

    return (result == MTA_CRYPT_RET_OK);
}