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

typedef struct {
    char *encrypted_data;
    int data_length;
    bool is_new_password;
    char* decryptedPassword;
    int decryptedPasswordLength;
} SharedPasswordData;

// Global variables
int password_length = 0;
int num_decrypters = 0;
int timeout_seconds = 30;
bool password_found = false;

static int iteration_count = 0;


// Shared data between threads
SharedPasswordData shared_password;
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
bool decrypt_password(const char* encrypted_password, unsigned int encrypted_length, const char* key, unsigned int key_length, char* decrypted_output, unsigned int* decrypted_length);
bool is_printable_data(const char* data, int length);
void print_spaces(int space_amount);
int count_digits(unsigned int number);
void print_readable_string(const char* data, int length);

int main(int argc, char* argv[]) {

    // if (argc != 5 && argc != 7) {
    //     printf("Usage: ");
    //     printf("encrypt.out [-t|--timeout <seconds>] ");
    //     printf("<-n|--num-of-decrypters <number>> ");
    //     printf("<-l|--password-length <length>>\n");
    //     return 1;
    // }

    // int arg_index = 1;

    // if (argc == 7) {

    //     if (strcmp(argv[arg_index], "-t") != 0 && strcmp(argv[arg_index], "--timeout") != 0) {
    //         printf("Missing timeout\n");
    //         return 1;
    //     }

    //     timeout_seconds = atoi(argv[arg_index + 1]);

    //     if (timeout_seconds <= 0) {
    //         printf("Timeout must be a positive integer.\n");
    //         return 1;
    //     }
    //     arg_index += 2;
    // }

    // if (strcmp(argv[arg_index], "-n") != 0 && strcmp(argv[arg_index], "--num-of-decrypters") != 0) {
    //     printf("Missing num of decrypters\n");
    //     return 1;
    // }

    // num_decrypters = atoi(argv[arg_index + 1]);

    // if (num_decrypters <= 0) {
    //     printf("Number of decrypters must be a positive integer.\n");
    //     return 1;
    // }

    // arg_index += 2;
    // if (strcmp(argv[arg_index], "-l") != 0 && strcmp(argv[arg_index], "--password-length") != 0) {
    //     printf("Missing password length\n");
    //     return 1;
    // }

    // password_length = atoi(argv[arg_index + 1]);

    // if (password_length <= 0 || password_length % 8 != 0) {
    //     printf("Password length must be a positive multiple of 8.\n");
    //     return 1;
    // }

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
    shared_password.encrypted_data = malloc(password_length);
    shared_password.decryptedPassword = malloc(password_length);
    if (!shared_password.encrypted_data || !shared_password.decryptedPassword) {
        printf("Failed to allocate shared data buffer\n");
        return 1;
    }

    // Initialize shared data
    shared_password.is_new_password = false;

    // Create decrypter threads
    decrypter_threads = malloc(sizeof(pthread_t) * num_decrypters);
    if (!decrypter_threads) {
        printf("Failed to allocate thread array\n");
        free(shared_password.encrypted_data);
        free(shared_password.decryptedPassword);
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
        free(shared_password.encrypted_data);
        free(shared_password.decryptedPassword);
        free(decrypter_threads);
        return 1;    
    }



    // Wait for threads to complete (though they run indefinitely)
    pthread_join(encrypter_thread, NULL);
    for (int i = 0; i < num_decrypters; ++i) {
        pthread_join(decrypter_threads[i], NULL);
    }

    // Cleanup 
    free(shared_password.encrypted_data);
    free(shared_password.decryptedPassword);
    free(decrypter_threads);
    free(decrypter_args);

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
    char* decrypted_output = malloc(password_length);

    if (!encryption_key || !originalPassword || !decrypted_output) {
        printf("Memory allocation failed in encrypter thread\n");
        exit(EXIT_FAILURE);
    }

    while (true) {
        // Generate new password and key
        generate_random_key(encryption_key, password_length / 8);
        generate_random_password(originalPassword, password_length);

        // Encrypt and update shared state
        pthread_mutex_lock(&shared_data_mutex);
        
        //encrypting the password
        encrypt_password(originalPassword, encryption_key, shared_password.encrypted_data, password_length);
        //inithialize shared password data
        shared_password.data_length = password_length;
        shared_password.is_new_password = true;
        password_found = false;
        iteration_count = 0;

        printf("%ld [SERVER]      [INFO] New password generated: ", time(NULL));
        print_readable_string(originalPassword, password_length);
        printf(", key: ");
        print_readable_string(encryption_key, password_length / 8);
        printf(", After encryption: ");
        print_readable_string(shared_password.encrypted_data, password_length);
        printf("\n");

        // Notify all decrypters to start trying to crack this new password
        pthread_cond_broadcast(&new_password_condition);
        pthread_mutex_unlock(&shared_data_mutex);

        // Wait until either the password is cracked or timeout occurs
       time_t start_time = time(NULL);
        pthread_mutex_lock(&shared_data_mutex);
        while (!password_found && difftime(time(NULL), start_time) < timeout_seconds) {
            // Wait for decrypters to signal they have a password to check
            pthread_cond_wait(&password_ready_to_be_checked, &shared_data_mutex);

            if (strcmp(shared_password.decryptedPassword, originalPassword) == 0) {
                password_found = true;
                printf("%ld [SERVER]      [OK]   Password decrypted successfully by client, received(", time(NULL));
                print_readable_string(shared_password.decryptedPassword, password_length);
                printf("), is (");
                print_readable_string(originalPassword, password_length);
                printf(")\n");
            }
                // printf("%ld [SERVER]      [OK]   Password decrypted successfully by client, received(%.*s), is (%.*s)\n",
                //     time(NULL),
                //     password_length, shared_password.decryptedPassword,
                //     password_length, originalPassword);
            // } else {
            //     printf("[Encrypter] Incorrect attempt\n\n");
            // }
            pthread_cond_broadcast(&continue_decryption_condition);
        }
        
        if (!password_found) {
            printf("[Encrypter] Timeout reached\n\n");
            pthread_cond_broadcast(&new_password_condition);
        }
        pthread_mutex_unlock(&shared_data_mutex);
        
        // Reset for next round
        shared_password.is_new_password = false;
    }
    // Cleanup
    free(encryption_key);
    free(originalPassword);
    free(decrypted_output);
    return NULL;
}

void* password_decrypter_task(void* arg) {
    int thread_id = *((int*)arg);
    char* trial_key = malloc(password_length / 8);
    char* decrypted_output = malloc(password_length);
    unsigned int decrypted_length = 0;

    if (!trial_key || !decrypted_output) {
        printf("Memory allocation failed in decrypter thread #%d\n", thread_id);
        exit(EXIT_FAILURE);
    }

    while (true) {
        pthread_mutex_lock(&shared_data_mutex);
        pthread_cond_wait(&new_password_condition, &shared_data_mutex);
        pthread_mutex_unlock(&shared_data_mutex);
        
        while (true) {
            generate_random_key(trial_key, password_length / 8);
            iteration_count++;

            pthread_mutex_lock(&shared_data_mutex);

            if (!password_found &&
                decrypt_password(shared_password.encrypted_data, shared_password.data_length,
                                 trial_key, password_length / 8, decrypted_output, &decrypted_length)) {

                password_found = true;

                memcpy(shared_password.decryptedPassword, decrypted_output, password_length);
                shared_password.decryptedPasswordLength = password_length;

                printf("%ld [CLIENT #%d]", time(NULL), thread_id);
                print_spaces(4 - count_digits(thread_id));
                printf("[INFO] After decryption(");
                print_readable_string(decrypted_output, password_length);
                printf("), key guessed(");
                print_readable_string(trial_key, password_length / 8);
                printf("), sending to server after %d iterations\n", iteration_count);

                // printf("%ld [CLIENT #%d]", time(NULL), thread_id);
                // print_spaces(4 - count_digits(thread_id));
                // printf("[INFO] Attempted decryption(%.*s), key guessed(%.*s), sending to server after %d iterations\n",
                //     password_length, decrypted_output,
                //     password_length / 8, trial_key,
                //     iteration_count);

                pthread_cond_signal(&password_ready_to_be_checked);
                pthread_cond_wait(&continue_decryption_condition, &shared_data_mutex);
                pthread_mutex_unlock(&shared_data_mutex);
                break;
            }

            pthread_mutex_unlock(&shared_data_mutex);

            if (password_found) {
                break;
            }
        }
    }

    free(trial_key);
    free(decrypted_output);
    return NULL;
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

/*id* password_decrypter_task(void* arg) {
    int thread_id = *((int*)arg);  // extract the thread ID
    char* trial_key = malloc(password_length / 8);
    char* decrypted_output = malloc(password_length);
    unsigned int decrypted_length = 0;

    if (!trial_key || !decrypted_output) {
        printf("Memory allocation failed in decrypter thread #%d\n", thread_id);
        exit(EXIT_FAILURE);
    }

    while (true) {
        pthread_mutex_lock(&shared_data_mutex);
        pthread_cond_wait(&new_password_condition, &shared_data_mutex);
        pthread_mutex_unlock(&shared_data_mutex);

        while (true) {
            pthread_mutex_lock(&shared_data_mutex);
            generate_random_key(trial_key, password_length / 8);
            if (decrypt_password(shared_password.encrypted_data, shared_password.data_length, trial_key, password_length / 8, decrypted_output, &decrypted_length)) {
                if (password_found) {
                    pthread_mutex_unlock(&shared_data_mutex);
                    break;
                }

                memcpy(shared_password.decryptedPassword, decrypted_output, password_length);
                shared_password.decryptedPasswordLength = password_length;
                printf("[Decrypter #%d] Submitted password: %.*s\n", thread_id, password_length, decrypted_output);

                pthread_cond_signal(&password_ready_to_be_checked);
                pthread_cond_wait(&continue_decryption_condition, &shared_data_mutex);
                if (password_found) {
                    pthread_mutex_unlock(&shared_data_mutex);
                    break;
                }
            }
            pthread_mutex_unlock(&shared_data_mutex);
        }
    }

    free(trial_key);
    free(decrypted_output);
    return NULL;
}*/



void generate_random_key(char* buffer, int length) {
    MTA_get_rand_data((char*)buffer, length);
}

void generate_random_password(char* buffer, int length) {
    MTA_get_rand_data((char*)buffer, length);

    while (!is_printable_data((char*)buffer, length)){
        MTA_get_rand_data((char*)buffer, length); // Regenerate until we get a printable password
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

bool decrypt_password(const char* encrypted_password, unsigned int encrypted_length, const char* key, unsigned int key_length, char* decrypted_output, unsigned int* decrypted_length) {
   
    // Perform the decryption
    MTA_CRYPT_RET_STATUS result = MTA_decrypt((char*)key, key_length, (char*)encrypted_password, encrypted_length, decrypted_output, decrypted_length);
    if (!is_printable_data(decrypted_output, *decrypted_length)) {//checks if the decrypted data is printable
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
                if (isprint(c))
                    printf("%c", c);
                
        }
    }
}