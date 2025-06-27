#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <stdbool.h>
#include "mta_crypt.h"
#include "mta_rand.h"
#include "Queue.h"


// Global variables
int password_length = 0;
int num_decrypters = 0;
int timeout_seconds = 30;
char *encrypted_data;//shared encrypted password data between threads
queue* password_queue_for_encrypter = NULL; // Queue to hold passwords to be checked

static int iteration_count = 0;


// Shared data between threads
pthread_mutex_t shared_data_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t new_password_condition = PTHREAD_COND_INITIALIZER;
pthread_cond_t password_ready_to_be_checked = PTHREAD_COND_INITIALIZER;
pthread_cond_t continue_decryption_condition = PTHREAD_COND_INITIALIZER;




// Function declarations
void* password_encrypter_task();
void* password_decrypter_task(void* arg);
void initialize_cryptography();
void generate_random_key(char* buffer, int length);
void generate_random_password(char* buffer, int length);
void encrypt_password(const char* plaintext, const char* key, char* encrypted_output, int length);
bool decrypt_password(const char* encrypted_password, unsigned int encrypted_length, const char* key, char* decrypted_output);
bool is_printable_data(const char* data, int length);
void print_spaces(int space_amount);
int count_digits(unsigned int number);
void print_readable_string(const char* data, int length);
void print_decrypter_password_sent(int thread_id, const char* decrypted_output, const char* trial_key);
void print_new_password_generated(char* originalPassword, char* encryption_key, char* encrypted_data);
void print_successful_encrypter(SharedPasswordData password_checked, char* originalPassword);
void print_timeout_reached();
void print_wrong_password(char* originalPassword, SharedPasswordData password_checked);
void queue_clear(queue* queue);
bool isTheSameString(const char* str1, const char* str2, int length);


int main(int argc, char* argv[]) {

    bool found_num_decrypters = false;
    bool found_password_length = false;

    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--num-of-decrypters") == 0) && i + 1 < argc) {
            num_decrypters = atoi(argv[i + 1]);
            found_num_decrypters = true;
        }

        else if ((strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--password-length") == 0) && i + 1 < argc) {
            password_length = atoi(argv[i + 1]);
            found_password_length = true;
        }

        else if ((strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--timeout") == 0) && i + 1 < argc) {
            timeout_seconds = atoi(argv[i + 1]);
        }
    }

    if (!found_num_decrypters) {
        printf("Missing num of decrypters\n");
        printf("Usage: encrypt.out [-t|--timeout <seconds>] ");
        printf("<-n|--num-of-decrypters <number>> <-l|--password-length <length>>\n");
        return 1;
    }

    if (!found_password_length) {
        printf("Missing password length\n");
        printf("Usage: encrypt.out [-t|--timeout <seconds>] ");
        printf("<-n|--num-of-decrypters <number>> <-l|--password-length <length>>\n");
        return 1;
    }

    if (num_decrypters <= 0) {
        printf("Number of decrypters must be a positive integer\n");
        printf("Usage: encrypt.out [-t|--timeout <seconds>] ");
        printf("<-n|--num-of-decrypters <number>> <-l|--password-length <length>>\n");
        return 1;
    }

    if (password_length <= 0 || password_length % 8 != 0) {
        printf("Password length must be a positive multiple of 8\n");
        printf("Usage: encrypt.out [-t|--timeout <seconds>] ");
        printf("<-n|--num-of-decrypters <number>> <-l|--password-length <length>>\n");
        return 1;
    }
            
    pthread_t encrypter_thread;
    pthread_t* decrypter_threads;

    // Initialize cryptographic system
    initialize_cryptography();

    // Allocate shared data buffer
    encrypted_data = malloc(password_length);
    if (!encrypted_data) {
        printf("Failed to allocate shared data buffer\n");
        return 1;
    }


    // Create decrypter threads
    decrypter_threads = malloc(sizeof(pthread_t) * num_decrypters);
    if (!decrypter_threads) {
        printf("Failed to allocate thread array\n");
        free(encrypted_data);
        return 1;
    }
    
    int* decrypter_args = malloc(sizeof(int)*num_decrypters);
    for (int i = 0; i < num_decrypters; ++i) {
        decrypter_args[i] = i + 1; // number from 1 to num_decrypters
        
        if (pthread_create(&decrypter_threads[i], NULL, password_decrypter_task, &decrypter_args[i]) != 0) {
            printf("Failed to create decrypter thread #%d\n", i + 1);
            exit(EXIT_FAILURE);
        }
    }
   

    // Start encrypter thread
    if (pthread_create(&encrypter_thread, NULL, password_encrypter_task, NULL) != 0) {
        printf("Failed to create encrypter thread");
        free(encrypted_data);
        free(decrypter_threads);
        return 1;    
    }

    // Wait for threads to complete (though they run indefinitely)
    pthread_join(encrypter_thread, NULL);
    for (int i = 0; i < num_decrypters; ++i) {
        pthread_join(decrypter_threads[i], NULL);
    }

    // Cleanup 
    free(encrypted_data);
    free(decrypter_threads);
    free(decrypter_args);

    queue_clear(password_queue_for_encrypter);
    free(password_queue_for_encrypter);

    return 0;
}

void initialize_cryptography() {
    MTA_CRYPT_RET_STATUS result = MTA_crypt_init();
    if (result != MTA_CRYPT_RET_OK) {
        printf("Cryptography initialization failed with error: %d\n", result);
        exit(EXIT_FAILURE);
    }
}

void* password_encrypter_task() {

    char* encryption_key = malloc(password_length / 8);
    char* originalPassword = malloc(password_length);

    bool password_found = false;


    if (!encryption_key || !originalPassword) {
        printf("Memory allocation failed in encrypter thread\n");
        exit(EXIT_FAILURE);
    }

    password_queue_for_encrypter = createQueue();//created the queue for passwords to be checked from decrypter threads


    while (true) {

        // Generate new password and key
        generate_random_key(encryption_key, password_length / 8);
        generate_random_password(originalPassword, password_length);
        
        //encrypting the password
        encrypt_password(originalPassword, encryption_key, encrypted_data, password_length);
        queue_clear(password_queue_for_encrypter); // Clear the queue after successful decryption

        //inithialize shared password data
        password_found = false;

        print_new_password_generated(originalPassword, encryption_key, encrypted_data);

        pthread_mutex_lock(&shared_data_mutex);
        iteration_count = 0;
        pthread_mutex_unlock(&shared_data_mutex);


        // Wait until either the password is cracked or timeout occurs
        time_t start_time = time(NULL);
        while (!password_found) {
            

            pthread_mutex_lock(&shared_data_mutex);

            while(isEmpty(password_queue_for_encrypter)) {
                // If the queue is empty, wait for a password to be sent by a decrypter thread
                pthread_cond_wait(&password_ready_to_be_checked, &shared_data_mutex);
            }
            

            SharedPasswordData password_to_check = dequeue(password_queue_for_encrypter);
            
            pthread_mutex_unlock(&shared_data_mutex);

            if(difftime(time(NULL), start_time) > timeout_seconds){
                break; // Exit the loop if timeout has not been reached
            }

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
    return NULL;
}

void* password_decrypter_task(void* arg) {

    int thread_id = *((int*)arg);
    char* trial_key = (char*)malloc(sizeof(char) * (password_length / 8));
    unsigned int decrypted_length = 0;

    if (!trial_key) {
        printf("Memory allocation failed in decrypter thread #%d\n", thread_id);
        exit(EXIT_FAILURE);
    }

    while (true) {

        generate_random_key(trial_key, password_length / 8);

        pthread_mutex_lock(&shared_data_mutex);
        iteration_count++;
        pthread_mutex_unlock(&shared_data_mutex);

        SharedPasswordData shared_password;
        shared_password.thread_id = thread_id;
        shared_password.decryptedPassword =  (char*)malloc(sizeof(char) * password_length);
        if (!shared_password.decryptedPassword) {
            printf("Memory allocation failed in decrypter thread #%d\n", thread_id);
            exit(EXIT_FAILURE);
        }


        if (decrypt_password(encrypted_data, password_length, trial_key, shared_password.decryptedPassword)) {

            pthread_mutex_lock(&shared_data_mutex);
            enqueue(password_queue_for_encrypter, shared_password);//add the decrypted password to the queue for encrypter thread
            

            print_decrypter_password_sent(thread_id, shared_password.decryptedPassword, trial_key);//print the decrypter result

            pthread_cond_signal(&password_ready_to_be_checked); // Signal the encrypter thread that a password is ready to be checked

            pthread_mutex_unlock(&shared_data_mutex);

                
        }
        else {
            free(shared_password.decryptedPassword);
        }

    }
       

    free(trial_key);
    return NULL;
}

void print_wrong_password(char* originalPassword, SharedPasswordData password_checked) {
    // Print the wrong password and key
    // This function is called when a password is checked but does not match the original
    printf("%ld     [SERVER]        [ERROR] Wrong password received from client #%d(", time(NULL), password_checked.thread_id);
    print_readable_string(password_checked.decryptedPassword, password_length);
    printf("), should be (");
    print_readable_string(originalPassword, password_length);
    printf(")");
    printf("\n");
}

void print_new_password_generated(char* originalPassword, char* encryption_key, char* encrypted_data) {
        // Print the new password and key
        // This function is called when a new password is generated by the encrypter thread
    printf("%ld     [SERVER]      [INFO]   New password generated: ", time(NULL));
    print_readable_string(originalPassword, password_length);
    printf(", key: ");
    print_readable_string(encryption_key, password_length / 8);
    printf(", After encryption: ");
    print_readable_string(encrypted_data, password_length);
    printf("\n");
}

void print_successful_encrypter(SharedPasswordData password_checked, char* originalPassword){
    
    printf("%ld     [SERVER]      [OK]     Password decrypted successfully by client #%d, received(", time(NULL), password_checked.thread_id);
    print_readable_string(password_checked.decryptedPassword, password_length);
    printf("), is (");
    print_readable_string(originalPassword, password_length);
    printf(")\n");
}

void print_timeout_reached(){
    printf("%ld     [SERVER]      [ERROR]  No password received during the configured timeout period (%d seconds), regenerating password", time(NULL), timeout_seconds);
    printf("\n");
}

int count_digits(unsigned int number) {
    int count = 0;

    do {
        count++;
        number /= 10;
    } while (number != 0);

    return count;
}

void print_spaces(int space_amount)
{
    for(int i = 0; i < space_amount; i++)
    {
        printf(" ");
    }
}

void print_decrypter_password_sent(int thread_id, const char* decrypted_output, const char* trial_key) {

    printf("%ld     [CLIENT #%d]", time(NULL), thread_id);
    print_spaces(4 - count_digits(thread_id));
    printf("[INFO]   After decryption(");
    print_readable_string(decrypted_output, password_length);
    printf("), key guessed(");
    print_readable_string(trial_key, password_length / 8);
    printf("), sending to server after %d iterations\n", iteration_count);
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


bool is_printable_data(const char* data, int length) {
    for (int i = 0; i < length; ++i) {
        if (!isprint(data[i])) {
            return false;
        }
    }
    return true;
}

bool decrypt_password(const char* encrypted_password, unsigned int encrypted_length, const char* key, char* decrypted_output) {
   
    // Perform the decryption
    MTA_CRYPT_RET_STATUS result = MTA_decrypt((char*)key, password_length/8, (char*)encrypted_password, encrypted_length, decrypted_output, &password_length);
    if (!is_printable_data(decrypted_output, password_length)) {//checks if the decrypted data is printable
        return false;
    }

    return (result == MTA_CRYPT_RET_OK);
}

void print_readable_string(const char* data, int length) {
    for (int i = 0; i < length; ++i) {
        unsigned char c = data[i];
        switch (c) {
            case '\n':
                printf("\\n");
                break;
            case '\r':
                printf("\\r");
                break;
            case '\t':
                printf("\\t");
                break;
            case '\0':
                printf("\\0");
                break;
            case '\\':
                printf("\\\\");
                break;
            default:
                printf("%c", c);
                
        }
    }
}

void queue_clear(queue* queue) {
    if (queue == NULL) return;

    pthread_mutex_lock(&shared_data_mutex);

    node* current = queue->front;
    while (current != NULL) {
        node* temp = current;
        current = current->next;

        free(temp->data.decryptedPassword);  // free the dynamically allocated string
        free(temp);        // free the node
    }

    queue->front = NULL;
    queue->back = NULL;

    pthread_mutex_unlock(&shared_data_mutex);
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