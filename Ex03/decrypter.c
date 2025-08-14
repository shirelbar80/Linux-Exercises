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
#include <ctype.h>
#include "mta_crypt.h"
#include "mta_rand.h"

#define ENCRYPTER_PIPE "/mnt/mta/encrypter_pipe"
#define DECRYPTER_PIPE_TEMPLATE "/mnt/mta/decrypter_pipe_%d"
#define BASE_DIR "/mnt/mta"
#define PIPE_PREFIX "decrypter_pipe_"
#define CONFIG_FILE "/mnt/mta/mtacrypt.conf"
#define DECRYPTER_LOG_FILE_TEMPLATE "/var/log/decrypter_log_%d.log"




typedef struct {
    int id;
    char* data;
    bool isPassword;
} PipeMsg;




void print_readable_string(const char* data, int length, FILE* log_file);
int get_next_available_id();
bool decrypt_password(const char* encrypted_password, unsigned int password_length, const char* key, char* decrypted_output);
void print_sent_subscription(int id, FILE* log_file);
void print_received_encrypted_password(int id, char* current_encrypted, int password_length, FILE* log_file);
void generate_random_key(char* buffer, int length);
void print_decrypted_password(int id, char* decrypt_password, int password_length, char* trial_key, int iteration_count, FILE* log_file);
bool is_printable_data(const char* data, int length);
void read_password_length_from_config(int* password_length);
void writeMsgToPipe(int pipeWriteEnd, PipeMsg msg, int password_length);
char* readPasswordFromPipe(int pipeReadEnd, int password_length);




int main() {
   
    int iteration_count = 0;
    int password_length = 0;

    read_password_length_from_config(&password_length);

    MTA_crypt_init();

    char* trial_key = (char*)malloc(sizeof(char) * (password_length / 8));
    char decrypter_pipe[128];
    char decrypter_log_path[128];
    int id = get_next_available_id();

    snprintf(decrypter_pipe, sizeof(decrypter_pipe), DECRYPTER_PIPE_TEMPLATE, id);

    snprintf(decrypter_log_path, sizeof(decrypter_log_path), DECRYPTER_LOG_FILE_TEMPLATE, id);

    //open the log file for the decrypter
    FILE *decrypter_log_file = fopen(decrypter_log_path, "w");  // "w" = write (overwrites file if exists)
    if (decrypter_log_file == NULL) {
        perror("fopen");
        return 1;
    }


    //open the named pipe for the decrypter
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
    PipeMsg msg;

    msg.data = malloc(password_length * sizeof(char));// Allocate memory for the data
    msg.id = id;
    msg.isPassword = false;

    writeMsgToPipe(fd_encrypter, msg, password_length);
    print_sent_subscription(id, decrypter_log_file);

    char* current_encrypted = NULL;

    fflush(decrypter_log_file);

    while (true) {


        //tries to read a new password from the encrypter pipe:
        //if doesnt read anything countinues as usual and else updates current_encrypted
        char* temp_data_encrypted = readPasswordFromPipe(fd_decrypter, password_length);
        if (temp_data_encrypted != NULL) {//new password was read
            
            iteration_count = 0;
            if (current_encrypted != NULL) {
                free(current_encrypted);
            }

            current_encrypted = temp_data_encrypted; 
            
            print_received_encrypted_password(id, current_encrypted, password_length, decrypter_log_file);
          
        }
               
        iteration_count++;//new iteration

        generate_random_key(trial_key, password_length / 8);

        if(decrypt_password(current_encrypted, password_length, trial_key, msg.data)){//generating a new guess

            print_decrypted_password(id, msg.data, password_length, trial_key, iteration_count, decrypter_log_file);

            msg.isPassword = true;

            writeMsgToPipe(fd_encrypter, msg, password_length);
        }
        
        fflush(decrypter_log_file);

    }
    
    fclose(decrypter_log_file);
    close(fd_decrypter);
    close(fd_encrypter);
    free(trial_key);
    free(msg.data);
    if (current_encrypted) free(current_encrypted);
    
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


bool decrypt_password(const char* encrypted_password, unsigned int password_length, const char* key, char* decrypted_output) {
   
    
    // Perform the decryption
    MTA_CRYPT_RET_STATUS result = MTA_decrypt((char*)key, password_length/8, (char*)encrypted_password, password_length, decrypted_output, &password_length);
    if (!is_printable_data(decrypted_output, password_length)) {//checks if the decrypted data is printable
        return false;
    }

    return (result == MTA_CRYPT_RET_OK);
}


void print_sent_subscription(int id, FILE* log_file){
    fprintf(log_file, "%ld     [CLIENT #%d]      [INFO]   Sent connect request to server\n", time(NULL), id);
}


void print_received_encrypted_password(int id, char* current_encrypted, int password_length, FILE* log_file) {
    fprintf(log_file , "%ld     [CLIENT #%d]      [INFO]   Recieved new encrypted password ", time(NULL), id);
    print_readable_string(current_encrypted, password_length, log_file);
    fprintf(log_file , "\n");

}


void generate_random_key(char* buffer, int length) {
    MTA_get_rand_data((char*)buffer, length);
}


void print_decrypted_password(int id, char* decrypt_password, int password_length, char* trial_key, int iteration_count, FILE* log_file){
    fprintf(log_file, "%ld     [CLIENT #%d]      [INFO]   Decrypted password: )", time(NULL), id);
    
    print_readable_string(decrypt_password, password_length, log_file);

    fprintf(log_file , " key: ");
    print_readable_string(trial_key, password_length / 8, log_file);
    fprintf(log_file, "  (in %d iterations)\n", iteration_count);
}

bool is_printable_data(const char* data, int length) {
    for (int i = 0; i < length; ++i) {
        if (!isprint(data[i])) {
            return false;
        }
    }
    return true;
}


void read_password_length_from_config(int* password_length){

    FILE* config = fopen(CONFIG_FILE, "r");
    if (!config) {
        perror("Failed to open config file");
        exit(EXIT_FAILURE);
    }

    char line[256];  
    if (fgets(line, sizeof(line), config) == NULL) {
        perror("Failed to read config line");
        fclose(config);
        exit(EXIT_FAILURE);
    }

    fclose(config);

    if (strncmp(line, "PASSWORD_LENGTH=", 16) == 0) {
        *password_length = atoi(line + 16);
    } else {
        fprintf(stderr, "Invalid config format\n");
        exit(EXIT_FAILURE);
    }

    if (*password_length <= 0) {
        fprintf(stderr, "Invalid password length in config\n");
        exit(EXIT_FAILURE);
    }

    
}


void print_readable_string(const char* data, int length, FILE* log_file) {
    for (int i = 0; i < length; ++i) {
        unsigned char c = data[i];
        switch (c) {
            case '\n':
                fprintf(log_file, "\\n");
                break;
            case '\r':
                fprintf(log_file, "\\r");
                break;
            case '\t':
                fprintf(log_file, "\\t");
                break;
            case '\0':
                fprintf(log_file, "\\0");
                break;
            case '\\':
                fprintf(log_file, "\\\\");
                break;
            default:
                fprintf(log_file, "%c", c);
                
        }
    }
}


void writeMsgToPipe(int pipeWriteEnd, PipeMsg msg, int password_length) {

    int len = 0;

    len = write(pipeWriteEnd, (void*)&msg.id , sizeof(msg.id));
    if (len < 0) { // Handle read error
        perror("write id");
        exit(EXIT_FAILURE);
    }

    len = write(pipeWriteEnd, (void*)&msg.isPassword, sizeof(msg.isPassword));
    if (len < 0 ) { 
        perror("write is_password");
        exit(EXIT_FAILURE);
    }

    if (msg.isPassword){//need to write the data only if it is a password
      
        len = write(pipeWriteEnd, (void*)msg.data, password_length * sizeof(char));
      
      if (len < 0) { 
        perror("write data");
        exit(EXIT_FAILURE);
       }
    }
}


char* readPasswordFromPipe(int pipeReadEnd, int password_length) {
    int len = 0;
    char* encrypt_data = malloc(password_length * sizeof(char));

    len = read(pipeReadEnd, (void*)encrypt_data, password_length * sizeof(char));
    if (len != password_length) { // Only accept full reads
        free(encrypt_data);
        return NULL;
    }

    return encrypt_data; // Return the read password    
}