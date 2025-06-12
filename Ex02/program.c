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
    unsigned char *encrypted_data;
    int data_length;
    bool is_new_password;
    unsigned char *current_trial_key;
    bool key_verified;
    bool stop_decryption;
} SharedPasswordData;

// Global variables
int password_length = 8;
int num_decrypters = 8;
int timeout_seconds = 100;
bool password_found = false;

// Shared data between threads
SharedPasswordData shared_password;
pthread_mutex_t shared_data_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t new_password_condition = PTHREAD_COND_INITIALIZER;
pthread_cond_t key_verified_condition = PTHREAD_COND_INITIALIZER;

// Function declarations
void* password_encrypter_task();
void* password_decrypter_task();
void initialize_cryptography();
void generate_random_key(unsigned char* buffer, int length);
void generate_random_password(unsigned char* buffer, int length);
void encrypt_password(const unsigned char* plaintext, const unsigned char* key, unsigned char* encrypted_output, int length);
bool verify_key(const unsigned char* encrypted, const unsigned char* key, unsigned char* decrypted_output, int length);
bool is_printable_data(const unsigned char* data, int length);

int main(int argc, char* argv[]) {
    pthread_t encrypter_thread;
    pthread_t* decrypter_threads;

    // Initialize cryptographic system
    initialize_cryptography();

    // Allocate shared data buffer
    shared_password.encrypted_data = malloc(password_length);
    shared_password.current_trial_key = malloc(password_length / 8);
    if (!shared_password.encrypted_data || !shared_password.current_trial_key) {
        printf("Failed to allocate shared data buffer\n");
        return 1;
    }

    // Initialize shared data
    shared_password.is_new_password = false;
    shared_password.key_verified = false;
    shared_password.stop_decryption = false;

    // Create worker threads
    decrypter_threads = malloc(sizeof(pthread_t) * num_decrypters);
    if (!decrypter_threads) {
        printf("Failed to allocate thread array\n");
        free(shared_password.encrypted_data);
        free(shared_password.current_trial_key);
        return 1;    
    }

    // Start encrypter thread
    if (pthread_create(&encrypter_thread, NULL, password_encrypter_task, NULL) != 0) {
        printf("Failed to create encrypter thread");
        free(shared_password.encrypted_data);
        free(shared_password.current_trial_key);
        free(decrypter_threads);
        return 1;    
    }

    // Start decrypter threads
    for (int i = 0; i < num_decrypters; ++i) {
        if (pthread_create(&decrypter_threads[i], NULL, password_decrypter_task, NULL) != 0) {
            printf("Failed to create decrypter thread");
            // Clean up already created threads
            for (int j = 0; j < i; ++j) {
                pthread_cancel(decrypter_threads[j]);
            }
            pthread_cancel(encrypter_thread);
            free(shared_password.encrypted_data);
            free(shared_password.current_trial_key);
            free(decrypter_threads);
            return 1;
        }
    }

    // Wait for threads to complete (though they run indefinitely)
    pthread_join(encrypter_thread, NULL);
    for (int i = 0; i < num_decrypters; ++i) {
        pthread_join(decrypter_threads[i], NULL);
    }

    // Cleanup (though we'll never reach here in this design)
    free(shared_password.encrypted_data);
    free(shared_password.current_trial_key);
    free(decrypter_threads);

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
    unsigned char* encryption_key = malloc(password_length / 8);
    unsigned char* plaintext_password = malloc(password_length);
    unsigned char* decrypted_output = malloc(password_length);

    if (!encryption_key || !plaintext_password || !decrypted_output) {
        printf("Memory allocation failed in encrypter thread\n");
        exit(EXIT_FAILURE);
    }

    while (true) {
        // Generate new password and key
        generate_random_key(encryption_key, password_length / 8);
        generate_random_password(plaintext_password, password_length);

        // Encrypt and update shared state
        pthread_mutex_lock(&shared_data_mutex);
        
        encrypt_password(plaintext_password, encryption_key, shared_password.encrypted_data, password_length);
        shared_password.data_length = password_length;
        shared_password.is_new_password = true;
        shared_password.key_verified = false;
        shared_password.stop_decryption = false;
        password_found = false;

        printf("[Encrypter] New password encrypted and ready for cracking\n");
        printf("[Encrypter] Actual password: %.*s\n", password_length, plaintext_password);

        // Notify all decrypters to start trying to crack this new password
        pthread_cond_broadcast(&new_password_condition);
        pthread_mutex_unlock(&shared_data_mutex);

        // Wait until either the password is cracked or timeout occurs
        time_t start_time = time(NULL);
        while (true) {
            pthread_mutex_lock(&shared_data_mutex);
            
            // Check if a new key was submitted for verification
            while (!shared_password.key_verified && !password_found && 
                   difftime(time(NULL), start_time) < timeout_seconds) {
                pthread_cond_wait(&key_verified_condition, &shared_data_mutex);
            }

            if (password_found) {
                printf("[Encrypter] Password was cracked!\n");
                pthread_mutex_unlock(&shared_data_mutex);
                break;
            }

            if (difftime(time(NULL), start_time) >= timeout_seconds) {
                printf("[Encrypter] Timeout reached, generating new password\n");
                shared_password.stop_decryption = true;
                pthread_mutex_unlock(&shared_data_mutex);
                break;
            }

            // Verify the submitted key
            if (shared_password.key_verified) {
                bool is_valid = verify_key(shared_password.encrypted_data, 
                                         shared_password.current_trial_key,
                                         decrypted_output,
                                         password_length);
                
                if (is_valid) {
                    password_found = true;
                    printf("[Encrypter] Valid key found! Password: %.*s\n", password_length, decrypted_output);
                    shared_password.stop_decryption = true;
                    pthread_mutex_unlock(&shared_data_mutex);
                    break;
                } else {
                    shared_password.key_verified = false;
                    pthread_cond_broadcast(&key_verified_condition);
                }
            }
            
            pthread_mutex_unlock(&shared_data_mutex);
        }

        // Reset for next round
        pthread_mutex_lock(&shared_data_mutex);
        shared_password.is_new_password = false;
        pthread_mutex_unlock(&shared_data_mutex);
    } 

    free(encryption_key);
    free(plaintext_password);
    free(decrypted_output);
    return NULL;
}

void* password_decrypter_task() {
    unsigned char* trial_key = malloc(password_length / 8);
    SharedPasswordData local_copy;

    if (!trial_key) {
        printf("Memory allocation failed in decrypter thread\n");
        exit(EXIT_FAILURE);
    }

    while (true) {
        // Wait for new password to be available
        pthread_mutex_lock(&shared_data_mutex);

        while (!shared_password.is_new_password) {
            pthread_cond_wait(&new_password_condition, &shared_data_mutex);
        }

        // Make a local copy of the encrypted data
        local_copy.encrypted_data = malloc(password_length);
        if (!local_copy.encrypted_data) {
            printf("Failed to allocate local data buffer\n");
            pthread_mutex_unlock(&shared_data_mutex);
            exit(1);
        }

        memcpy(local_copy.encrypted_data, shared_password.encrypted_data, password_length);
        local_copy.data_length = shared_password.data_length;

        pthread_mutex_unlock(&shared_data_mutex);

        // Attempt to crack the password
        while (true) {
            pthread_mutex_lock(&shared_data_mutex);
            
            // Check if we should stop
            if (password_found || shared_password.stop_decryption || !shared_password.is_new_password) {
                pthread_mutex_unlock(&shared_data_mutex);
                break;
            }

            // Generate a new trial key
            generate_random_key(trial_key, password_length / 8);
            
            // Submit the key for verification
            memcpy(shared_password.current_trial_key, trial_key, password_length / 8);
            shared_password.key_verified = true;
            
            // Notify the encrypter
            pthread_cond_signal(&key_verified_condition);
            
            // Wait for verification result
            while (shared_password.key_verified && !password_found && !shared_password.stop_decryption) {
                pthread_cond_wait(&key_verified_condition, &shared_data_mutex);
            }
            
            pthread_mutex_unlock(&shared_data_mutex);
        }

        free(local_copy.encrypted_data);
    }

    free(trial_key);
    return NULL;
}

void generate_random_key(unsigned char* buffer, int length) {
    MTA_get_rand_data((char*)buffer, length);
}

void generate_random_password(unsigned char* buffer, int length) {
    MTA_get_rand_data((char*)buffer, length);
}

void encrypt_password(const unsigned char* plaintext, const unsigned char* key, unsigned char* encrypted_output, int length) {
    unsigned int encrypted_length = 0;
    MTA_CRYPT_RET_STATUS result = MTA_encrypt((char*)key, length/8, (char*)plaintext, length, (char*)encrypted_output, &encrypted_length);
    if (result != MTA_CRYPT_RET_OK) {
        printf("Encryption failed with error: %d\n", result);
        exit(1);
    }
}

bool verify_key(const unsigned char* encrypted, const unsigned char* key, unsigned char* decrypted_output, int length) {
    unsigned int decrypted_length = 0;
    MTA_CRYPT_RET_STATUS result = MTA_decrypt((char*)key, length/8, (char*)encrypted, length, (char*)decrypted_output, &decrypted_length);
    if (result != MTA_CRYPT_RET_OK) {
        return false;
    }
    return is_printable_data(decrypted_output, length);
}

bool is_printable_data(const unsigned char* data, int length) {
    for (int i = 0; i < length; ++i) {
        if (!isprint(data[i])) {
            return false;
        }
    }
    return true;
}