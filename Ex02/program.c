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
} SharedPasswordData;

// Global configuration
int g_password_length = 8;
int g_num_decrypters = 10;
int g_timeout_seconds = 20;
bool g_password_found = false;

// Shared data between threads
SharedPasswordData g_shared_password;
pthread_mutex_t g_shared_data_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t g_new_password_condition = PTHREAD_COND_INITIALIZER;

// Function declarations
void* password_encrypter_task();
void* password_decrypter_task();
void initialize_cryptography();
void generate_random_key(unsigned char* buffer, int length);
void generate_random_password(unsigned char* buffer, int length);
void encrypt_password(const unsigned char* plaintext, const unsigned char* key, unsigned char* encrypted_output, int length);
bool decrypt_password(const unsigned char* encrypted, const unsigned char* key, unsigned char* decrypted_output, int length);
bool is_printable_data(const unsigned char* data, int length);

int main(int argc, char* argv[]) {
    pthread_t encrypter_thread;
    pthread_t* decrypter_threads;

    // Initialize cryptographic system
    initialize_cryptography();

    // Allocate shared data buffer
    g_shared_password.encrypted_data = malloc(g_password_length);
    if (!g_shared_password.encrypted_data) {
        printf("Failed to allocate shared data buffer\n");
        return 1;
    }

    // Create worker threads
    decrypter_threads = malloc(sizeof(pthread_t) * g_num_decrypters);
    if (!decrypter_threads) {
        printf("Failed to allocate thread array\n");
        free(g_shared_password.encrypted_data);
        return 1;    
    }

    // Start encrypter thread
    if (pthread_create(&encrypter_thread, NULL, password_encrypter_task, NULL) != 0) {
        perror("Failed to create encrypter thread");
        free(g_shared_password.encrypted_data);
        free(decrypter_threads);
        return 1;    
    }

    // Start decrypter threads
    for (int i = 0; i < g_num_decrypters; ++i) {
        if (pthread_create(&decrypter_threads[i], NULL, password_decrypter_task, NULL) != 0) {
            printf("Failed to create decrypter thread");
            // Clean up already created threads
            for (int j = 0; j < i; ++j) {
                pthread_cancel(decrypter_threads[j]);
            }
            pthread_cancel(encrypter_thread);
            free(g_shared_password.encrypted_data);
            free(decrypter_threads);
            return 1;
        }
    }

    // Wait for threads to complete (though they run indefinitely)
    pthread_join(encrypter_thread, NULL);
    for (int i = 0; i < g_num_decrypters; ++i) {
        pthread_join(decrypter_threads[i], NULL);
    }

    // Cleanup (though we'll never reach here in this design)
    free(g_shared_password.encrypted_data);
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
    unsigned char* encryption_key = malloc(g_password_length / 8);
    unsigned char* plaintext_password = malloc(g_password_length);

    if (!encryption_key || !plaintext_password) {
        fprintf(stderr, "Memory allocation failed in encrypter thread\n");
        exit(EXIT_FAILURE);
    }

    while (true) {
        // Generate new password and key
        generate_random_key(encryption_key, g_password_length / 8);
        generate_random_password(plaintext_password, g_password_length);

        // Encrypt and update shared state
        pthread_mutex_lock(&g_shared_data_mutex);
        encrypt_password(plaintext_password, encryption_key,
                         g_shared_password.encrypted_data, g_password_length);
        g_shared_password.data_length = g_password_length;
        g_shared_password.is_new_password = true;
        g_password_found = false;

        printf("[Encrypter] New password encrypted and ready for cracking\n");

        // Notify all decrypters to start trying to crack this new password
        pthread_cond_broadcast(&g_new_password_condition);
        pthread_mutex_unlock(&g_shared_data_mutex);

        // Wait until either the password is cracked or timeout occurs
        time_t start_time = time(NULL);
        while (true) {
            pthread_mutex_lock(&g_shared_data_mutex);
            bool cracked = g_password_found;
            pthread_mutex_unlock(&g_shared_data_mutex);

            if (cracked || difftime(time(NULL), start_time) >= g_timeout_seconds) {
                break;
            }

            sleep(1); // sleep for 100ms
        }

        pthread_mutex_lock(&g_shared_data_mutex);
        if (g_password_found) {
            printf("[Encrypter] Password was cracked!\n");
        } else {
            printf("[Encrypter] Timeout reached, generating new password\n");
        }
        // Reset the signal flag so decrypters can wait for the next one
        g_shared_password.is_new_password = false;
        pthread_mutex_unlock(&g_shared_data_mutex);

        sleep(1); // optional pause before generating the next password
    }

    free(encryption_key);
    free(plaintext_password);
    return NULL;
}


void* password_decrypter_task() {
    unsigned char* trial_key = malloc(g_password_length / 8);
    unsigned char* decrypted_output = malloc(g_password_length);
    SharedPasswordData local_copy;

    if (!trial_key || !decrypted_output) {
        fprintf(stderr, "Memory allocation failed in decrypter thread\n");
        exit(EXIT_FAILURE);
    }

    while (true) {
        // Wait for new password to be available
        pthread_mutex_lock(&g_shared_data_mutex);

        while (!g_shared_password.is_new_password) {
            pthread_cond_wait(&g_new_password_condition, &g_shared_data_mutex);
        }

        // Make a local copy of the encrypted data (do not reset is_new_password)
        local_copy.encrypted_data = malloc(g_password_length);
        if (!local_copy.encrypted_data) {
            printf("Failed to allocate local data buffer\n");
            pthread_mutex_unlock(&g_shared_data_mutex);
            exit(1);
        }

        memcpy(local_copy.encrypted_data, g_shared_password.encrypted_data, g_password_length);
        local_copy.data_length = g_shared_password.data_length;

        pthread_mutex_unlock(&g_shared_data_mutex);

        // Attempt to crack the password until cracked or timeout
        while (true) {
            // Check if password already cracked
            pthread_mutex_lock(&g_shared_data_mutex);
            bool cracked = g_password_found || !g_shared_password.is_new_password;
            pthread_mutex_unlock(&g_shared_data_mutex);

            if (cracked) break;

            generate_random_key(trial_key, g_password_length / 8);

            if (decrypt_password(local_copy.encrypted_data, trial_key, decrypted_output, g_password_length)) {
                pthread_mutex_lock(&g_shared_data_mutex);

                if (!g_password_found) {
                    g_password_found = true;
                    printf("[Decrypter] Found valid key! Password: %.*s\n", g_password_length, decrypted_output);
                    pthread_cond_signal(&g_new_password_condition);  // optional signal
                }

                pthread_mutex_unlock(&g_shared_data_mutex);
                break;
            }

            sleep(1); // Small sleep to prevent CPU overload
        }

        free(local_copy.encrypted_data);
    }

    // Never reached
    free(trial_key);
    free(decrypted_output);
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

bool decrypt_password(const unsigned char* encrypted, const unsigned char* key, unsigned char* decrypted_output, int length) {
    unsigned int decrypted_length = 0;
    MTA_CRYPT_RET_STATUS result = MTA_decrypt((char*)key, length/8, (char*)encrypted, length, (char*)decrypted_output, &decrypted_length);
    if (result != MTA_CRYPT_RET_OK) {
        fprintf(stderr, "Decryption failed with error: %d\n", result);
        exit(EXIT_FAILURE);
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