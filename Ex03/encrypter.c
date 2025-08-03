
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <stdbool.h>
#include "mta_crypt.h"
#include "mta_rand.h"
#include "linked_list.h"


#define DECRYPTER_PIPE_TEMPLATE "/mnt/mta/decrypter_pipe_%d"
#define ENCRYPTER_PIPE "/mnt/mta/encrypter_pipe"
#define CONFIG_FILE "/mnt/mta/mtacrypt.conf"
#define ENCRYPTER_LOG_FILE "/var/log/encrypter_log.log"




typedef struct {
    int id;
    char* data;
    bool isPassword;
} MsgFromDecrypter;

void generate_random_password(char* buffer, int length);
void generate_random_key(char* buffer, int length);
void encrypt_password(const char* plaintext, const char* key, char* encrypted_output, int length);
void print_successful_encrypter(int id, FILE* log_file);
void print_new_password_generated(int password_length, char* originalPassword, char* encryption_key, char* encrypted_data, FILE* log_file);
void print_readable_string(const char* data, int length, FILE* log_file);
void print_received_subscription(char* pipe_path, int id, FILE* log_file);
void read_password_length_from_config(int* password_length, FILE* encrypter_log_file);
bool isTheSameString(const char* str1, const char* str2, int length);


int main() {

    int password_length = 0;
    List decrypter_list = create_list();


    //open the log file for the decrypter
    FILE *encrypter_log_file = fopen(ENCRYPTER_LOG_FILE, "a");  // "w" = write (overwrites file if exists)
    if (encrypter_log_file == NULL) {
        perror("fopen");
        return 1;
    }

    read_password_length_from_config(&password_length, encrypter_log_file);

    // Create named pipe for encrypter
    mkfifo(ENCRYPTER_PIPE, 0666);
    
    int fd_encrypter = open(ENCRYPTER_PIPE, O_RDONLY | O_NONBLOCK);  // open in non-blocking mode
    if (fd_encrypter < 0) {
        perror("open encrypter pipe");
        exit(EXIT_FAILURE);
    }

    // Init encryption
    MTA_crypt_init();


    char* encryption_key = malloc((password_length / 8)*sizeof(char));
    char* originalPassword = malloc(password_length*sizeof(char));
    char* encrypted_data = malloc(password_length*sizeof(char));
    if (originalPassword == NULL || encryption_key == NULL || encrypted_data == NULL) {
        printf("Memory allocation failed in encrypter\n");
        exit(EXIT_FAILURE);
    }

    
    while (true){

        // Generate new password and key
        generate_random_key(encryption_key, password_length / 8);
        generate_random_password(originalPassword, password_length);
            
        //encrypting the password
        encrypt_password(originalPassword, encryption_key, encrypted_data, password_length);

        // Log the encrypted password
        print_new_password_generated(password_length,originalPassword, encryption_key, encrypted_data, encrypter_log_file);

        //sending encrypted password to all sbscripted decrypters
        Node* curr = decrypter_list.head;
        while(curr != NULL){

            write(curr->fd, encrypted_data, password_length);//send encrypted password to decrypter

            curr = curr->next;
        }


        MsgFromDecrypter msg;

        while ((read(fd_encrypter, &msg, sizeof(msg))) > 0) {
               
            if(msg.isPassword){//recieved password to check
                
                if(isTheSameString(msg.data, originalPassword, password_length)) {//password is correct

                    //write to log files that the password was decrypted successfully
                    print_successful_encrypter(msg.id, encrypter_log_file);//OK

                    break;
                }

            }
            else{//decrypter wants to receive encrypted password - subscription

                
                char decrypter_pipe[128];//name of dec pipe

                snprintf(decrypter_pipe, sizeof(decrypter_pipe), DECRYPTER_PIPE_TEMPLATE, msg.id);


                int fd_decrypter = open(decrypter_pipe, O_WRONLY);//open dec pipe
                if (fd_decrypter >= 0) {
                    write(fd_decrypter, encrypted_data, password_length);//send encrypted password to decrypter
                }

                append(&decrypter_list, msg.id, fd_decrypter);//added dec to the list

                print_received_subscription(decrypter_pipe, msg.id, encrypter_log_file);//print to log that subscription was received


            }
        }      
            
    }

    // close the encrypter pipe and free resources
    close(fd_encrypter);
    fclose(encrypter_log_file);
    free(encryption_key);
    free(originalPassword);

    //free list and close pipes
    Node* curr = decrypter_list.head;
    while (curr != NULL) {
        close(curr->fd); // Close each decrypter's pipe
        Node* temp = curr;
        curr = curr->next; // Move to the next node
        free(temp); // Free the current node        
    }

    return 0;

}
    


void print_new_password_generated(int password_length, char* originalPassword, char* encryption_key, char* encrypted_data, FILE* log_file) {
        // Print the new password and key
        // This function is called when a new password is generated by the encrypter thread
    fprintf(log_file, "%ld     [SERVER]      [INFO]   New password: ", time(NULL));
    print_readable_string(originalPassword, password_length, log_file);
    fprintf(log_file, ", key: ");
    print_readable_string(encryption_key, password_length / 8, log_file);
    fprintf(log_file, ", Encrypted: ");
    print_readable_string(encrypted_data, password_length, log_file);
    fprintf(log_file, "\n");

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



void print_successful_encrypter(int id, FILE* log_file) {
    
    fprintf(log_file, "%ld     [SERVER]      [OK]     Password decrypted successfully by decrypter #%d\n", time(NULL), id);
}




void print_received_subscription(char* pipe_path, int id, FILE* log_file) {
    fprintf(log_file, "%ld     [SERVER]      [INFO]   Received connection request from decrypter id %d, fifo name %s\n", time(NULL), id, pipe_path);
}



void read_password_length_from_config(int* password_length, FILE* encrypter_log_file){

    fprintf(encrypter_log_file, "Reading %s...\n", CONFIG_FILE);
   // Read password length from config
    FILE* config = fopen(CONFIG_FILE, "r");
    if (!config || fscanf(config, "%d", password_length) != 1 || *password_length <= 0) {
        perror("Failed to read config");
        exit(EXIT_FAILURE);
    }
    fprintf(encrypter_log_file, "Password length set to %d\n", *password_length);

    fclose(config);
}


void generate_random_key(char* buffer, int length) {
    MTA_get_rand_data((char*)buffer, length);
}

void generate_random_password(char* buffer, int length) {
  
    for(int i = 0; i < length; i++) {
        buffer[i] = MTA_get_rand_char();
        while(!isprint(buffer[i])) { // Ensure the character is printable
            buffer[i] = MTA_get_rand_char(); // Regenerate until we get a printable character
        }
    }
}

void encrypt_password(const char* plaintext, const char* key, char* encrypted_output, int length) {
    unsigned int encrypted_length = 0;
    MTA_CRYPT_RET_STATUS result = MTA_encrypt((char*)key, length/8, (char*)plaintext, length, (char*)encrypted_output, &encrypted_length);
    if (result != MTA_CRYPT_RET_OK) {
        printf("Encryption failed with error: %d\n", result);
        exit(1);
    }
}


bool isTheSameString(const char* str1, const char* str2, int length) {
    if (str1 == NULL || str2 == NULL) {
        return false;
    }

    for(int i = 0; i < length; i++) {
        if (str1[i] != str2[i]) {
            return false;
        }
    }

    return true;
}