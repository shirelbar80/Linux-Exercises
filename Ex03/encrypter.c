/**
 * encrypter.c - IPC encrypter logic using named pipes
 * Reads password length from /mnt/mta/conf.txt
 * Waits for decrypter subscriptions and sends current encrypted password via named pipes
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
#include <stdbool.h>
#include <time.h>
#include "mta_crypt.h"
#include "mta_rand.h"

#define ENCRYPTER_PIPE "/mnt/mta/encrypter_pipe"
#define CONFIG_FILE "/mnt/mta/conf.txt"
#define MAX_PASSWORD_LEN 256
#define MAX_KEY_LEN 64



typedef struct {
    int id;
    char* data;
    bool isPassword;
} MsgFromDecrypter;

void generate_random_password(char* buffer, int length);
void generate_random_key(char* buffer, int length);
void encrypt_password(const char* plaintext, const char* key, char* encrypted_output, int length);

int main() {
    int password_length = 0;

    // Read password length from config
    FILE* config = fopen(CONFIG_FILE, "r");
    if (!config || fscanf(config, "%d", &password_length) != 1 || password_length <= 0) {
        perror("Failed to read config");
        exit(EXIT_FAILURE);
    }
    fclose(config);

    // Create named pipe for encrypter
    mkfifo(ENCRYPTER_PIPE, 0666);
    
    int pipe_fd = open(ENCRYPTER_PIPE, O_RDONLY | O_NONBLOCK);  // open in non-blocking mode
    if (pipe_fd < 0) {
        perror("open encrypter pipe");
        exit(EXIT_FAILURE);
    }

    // Init encryption
    MTA_crypt_init();

    char* encryption_key = malloc(password_length / 8);
    char* originalPassword = malloc(password_length);
    char* encrypted_data = malloc(password_length);
    if (!encryption_key || !originalPassword) {
        printf("Memory allocation failed in encrypter thread\n");
        exit(EXIT_FAILURE);
    }

    bool password_found = false;

    // Generate new password and key
    generate_random_key(encryption_key, password_length / 8);
    generate_random_password(originalPassword, password_length);
        
    //encrypting the password
    encrypt_password(originalPassword, encryption_key, encrypted_data, password_length);

    
    while (true){

        MsgFromDecrypter msg;

        ssize_t len;
        while ((len = read(pipe_fd, &msg, sizeof(msg))) > 0) {
            if (len == sizeof(msg)) {//dont know
               
                if(msg.isPassword){//recieved password to check
                 
                    char* decrypted_output = malloc(password_length);
                    if (!decrypted_output) {
                        printf("Memory allocation failed for decrypted output\n");
                        exit(EXIT_FAILURE);
                    }

                    if(isTheSameString(msg.data, originalPassword, password_length)) {
                        password_found = true;

                        //log
                        print_successful_encrypter(msg.data, originalPassword);//OK

                    
                    }
                    else{
                        //log
                        print_wrong_password(originalPassword, msg.data);//ERROR

                    }
                    free(msg.data);


                }
                else{//decrypter wants to receive encrypted password

                    int out_fd = open(msg.data, O_WRONLY);
                    if (out_fd >= 0) {
                        write(out_fd, encrypted_data, password_length);
                        close(out_fd);
                    }
                }
                
            } 
            else {
                fprintf(stderr, "Partial message received (%zd bytes)\n", len);
            }
        }
    }



        


    











    //trashhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh


    while (true) {

        regenerate_password://label for jumping back to regenerate password

        // Generate new password and key
        generate_random_key(encryption_key, password_length / 8);
        generate_random_password(originalPassword, password_length);
        
        //encrypting the password
        encrypt_password(originalPassword, encryption_key, encrypted_data, password_length);

        //inithialize shared password data
        password_found = false;

        //log
        print_new_password_generated(originalPassword, encryption_key, encrypted_data);

   //iteration_count = 0;

        int fd = open(ENCRYPTER_PIPE, O_RDONLY);//open the named pipe for reading
        if (fd < 0) {
        perror("open encrypter pipe");  // Print error if pipe can't be opened
        continue;                       // Skip this iteration and try again
        }
     

        // Read the name of the decrypter's pipe from the encrypter pipe
        char decrypter_pipe[MAX_MSG_SIZE];
        ssize_t len = read(fd, decrypter_pipe, sizeof(decrypter_pipe));
        close(fd);  // Close the encrypter pipe after reading

        // If the read was successful and we got a pipe name
        if (len > 0) {
            decrypter_pipe[len] = '\0';  // Null-terminate the pipe name string

            // Open the decrypter's pipe for writing
            int out_fd = open(decrypter_pipe, O_WRONLY);
            if (out_fd >= 0) {
                // Send the encrypted password to the decrypter
                write(out_fd, encrypted_data, password_length);
                close(out_fd);  // Close the decrypter pipe
            }
        }

        // Wait until either the password is cracked or timeout occurs
        while (!password_found) {
            
            while (isEmpty(password_queue_for_encrypter)) {

                // Set timeout absolute time
                struct timespec timeout_time;
                clock_gettime(CLOCK_REALTIME, &timeout_time);
                timeout_time.tv_sec += timeout_seconds;

                while (isEmpty(password_queue_for_encrypter)) {
                    int wait_result = pthread_cond_timedwait(&password_ready_to_be_checked, &shared_data_mutex, &timeout_time);

                    if (wait_result == ETIMEDOUT) {
                        pthread_mutex_unlock(&shared_data_mutex);
                        print_timeout_reached();
                        goto regenerate_password; // jump to outer loop
                    }
                }
            }
            

            SharedPasswordData password_to_check = dequeue(password_queue_for_encrypter);
            
            pthread_mutex_unlock(&shared_data_mutex);

            

            if (isTheSameString(password_to_check.decryptedPassword, originalPassword, password_length)) {
                password_found = true;
                
                pthread_mutex_lock(&shared_data_mutex);
                
                print_successful_encrypter(password_to_check, originalPassword);//OK
                
                pthread_mutex_unlock(&shared_data_mutex);

                free(password_to_check.decryptedPassword);
                break; // Exit the loop if the password is found
            }
            else{
                pthread_mutex_lock(&shared_data_mutex);

                print_wrong_password(originalPassword, password_to_check);//ERROR
                pthread_mutex_unlock(&shared_data_mutex);

                free(password_to_check.decryptedPassword);
            }
                
        }
        
        if (!password_found) {
            print_timeout_reached();
        }
        
    }
    
    // Cleanup (will never be reached)
    free(encryption_key);
    free(originalPassword);
    return 0;
}
