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
#include "linked_list.h"

#define DECRYPTER_PIPE_TEMPLATE "/mnt/mta/decrypter_pipe_%d"
#define ENCRYPTER_PIPE "/mnt/mta/encrypter_pipe"
#define CONFIG_FILE "/mnt/mta/conf.txt"
#define MAX_PASSWORD_LEN 256
#define MAX_KEY_LEN 64



typedef struct {
    int id;
    char data[MAX_PASSWORD_LEN];
    bool isPassword;
} MsgFromDecrypter;

void generate_random_password(char* buffer, int length);
void generate_random_key(char* buffer, int length);
void encrypt_password(const char* plaintext, const char* key, char* encrypted_output, int length);
void print_successful_encrypter(int decrypter_id);



int main() {

    int password_length = 0;
    List decrypter_list = create_list();


    // Read password length from config
    FILE* config = fopen(CONFIG_FILE, "r");
    if (!config || fscanf(config, "%d", &password_length) != 1 || password_length <= 0) {
        perror("Failed to read config");
        exit(EXIT_FAILURE);
    }
    fclose(config);

    // Create named pipe for encrypter
    mkfifo(ENCRYPTER_PIPE, 0666);
    
    int fd_encrypter = open(ENCRYPTER_PIPE, O_RDONLY | O_NONBLOCK);  // open in non-blocking mode
    if (fd_encrypter < 0) {
        perror("open encrypter pipe");
        exit(EXIT_FAILURE);
    }

    // Init encryption
    MTA_crypt_init();


    char* encryption_key = malloc(password_length / 8);
    char* originalPassword = malloc(password_length);
    char encrypted_data[MAX_PASSWORD_LEN];
    if (originalPassword || encryption_key) {
        printf("Memory allocation failed in encrypter thread\n");
        exit(EXIT_FAILURE);
    }

    bool password_found = false;

    
    while (true){

        // Generate new password and key
        generate_random_key(encryption_key, password_length / 8);
        generate_random_password(originalPassword, password_length);
            
        //encrypting the password
        encrypt_password(originalPassword, encryption_key, encrypted_data, password_length);

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

                    //log
                    //print_successful_encrypter(msg.id);//OK

                    break;

                
                }
                else{
                    //log
                    print_wrong_password(originalPassword, msg.data);//ERROR

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


            }
        }      
            
    }

    /*void print_successful_encrypter(SharedPasswordData password_checked, char* originalPassword){
    
        printf("%ld     [SERVER]      [OK]     Password decrypted successfully by client #%d, received(", time(NULL), password_checked.thread_id);
        printf("), is (");
        print_readable_string(originalPassword, password_length);
        printf(")\n");
    }*/
    



        

}
