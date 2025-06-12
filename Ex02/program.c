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
int password_length = 16;
int num_decrypters = 3;
int timeout_seconds = 35;
bool password_found = false;

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

int main(int argc, char* argv[]) {
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

        printf("[Encrypter] New password encrypted and ready for cracking\n");
        printf("[Encrypter] Actual password: %.*s\n", password_length, originalPassword);

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
                printf("[Encrypter] Password cracked! Actual password: %.*s\n\n", password_length, shared_password.decryptedPassword);
            } else {
                printf("[Encrypter] Incorrect attempt\n\n");
            }
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
}



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