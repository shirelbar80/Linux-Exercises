#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <time.h>
#include <stdbool.h>
#include "mta_crypt.h"

typedef struct {
    unsigned char *encrypted;
    int length;
    bool new_password;
} EncryptedData;

int g_password_length = 32;
int g_num_decrypters = 4;
int g_timeout = 5;
bool g_found = false;

EncryptedData g_encrypted_data;
pthread_mutex_t g_data_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t g_new_password_cond = PTHREAD_COND_INITIALIZER;

void generate_and_encrypt(unsigned char *key_out, unsigned char *plain_out, unsigned char *encrypted_out, int length) {
    generate_random_key(key_out, length / 8);
    generate_random_password(plain_out, length);
    encrypt(plain_out, key_out, encrypted_out, length);
}

bool is_printable(unsigned char *data, int length) {
    for (int i = 0; i < length; ++i) {
        if (!isprint(data[i])) return false;
    }
    return true;
}

void *encrypter_thread(void *arg) {
    unsigned char *key = malloc(g_password_length / 8);
    unsigned char *plain = malloc(g_password_length);

    if (!key || !plain) {
        fprintf(stderr, "Failed to allocate buffers in encrypter thread\n");
        exit(EXIT_FAILURE);
    }

    while (1) {
        pthread_mutex_lock(&g_data_mutex);

        generate_and_encrypt(key, plain, g_encrypted_data.encrypted, g_password_length);
        g_encrypted_data.length = g_password_length;
        g_encrypted_data.new_password = true;
        g_found = false;

        pthread_cond_broadcast(&g_new_password_cond);
        printf("New encrypted password generated.\n");

        time_t start = time(NULL);
        while (!g_found && difftime(time(NULL), start) < g_timeout) {
            pthread_cond_wait(&g_new_password_cond, &g_data_mutex);
        }

        if (g_found) {
            printf("Password cracked!\n");
        } else {
            printf("Timeout reached. Generating new password.\n");
        }

        pthread_mutex_unlock(&g_data_mutex);
        sleep(1);
    }

    free(key);
    free(plain);
    return NULL;
}

void *decrypter_thread(void *arg) {
    unsigned char *try_key = malloc(g_password_length / 8);
    unsigned char *decrypted = malloc(g_password_length);
    EncryptedData local_data;

    if (!try_key || !decrypted) {
        fprintf(stderr, "Failed to allocate buffers in decrypter thread\n");
        exit(EXIT_FAILURE);
    }

    while (1) {
        pthread_mutex_lock(&g_data_mutex);

        while (!g_encrypted_data.new_password)
            pthread_cond_wait(&g_new_password_cond, &g_data_mutex);

        local_data.encrypted = malloc(g_password_length);
        if (!local_data.encrypted) {
            fprintf(stderr, "Failed to allocate local_data.encrypted\n");
            exit(EXIT_FAILURE);
        }

        memcpy(local_data.encrypted, g_encrypted_data.encrypted, g_password_length);
        local_data.length = g_encrypted_data.length;
        local_data.new_password = g_encrypted_data.new_password;
        g_encrypted_data.new_password = false;

        pthread_mutex_unlock(&g_data_mutex);

        while (!g_found) {
            generate_random_key(try_key, g_password_length / 8);
            decrypt(local_data.encrypted, try_key, decrypted, g_password_length);

            if (is_printable(decrypted, g_password_length)) {
                pthread_mutex_lock(&g_data_mutex);

                if (!g_found) {
                    g_found = true;
                    pthread_cond_signal(&g_new_password_cond);
                    printf("Decrypter found key: %.*s\n", g_password_length, decrypted);
                }

                pthread_mutex_unlock(&g_data_mutex);
                break;
            }
        }

        free(local_data.encrypted);
    }

    free(try_key);
    free(decrypted);
    return NULL;
}

void parse_arguments(int argc, char *argv[]) {
    // Dummy implementation — fill in as needed
    // You can add logic here to parse --length, --threads, --timeout, etc.
}

int main(int argc, char *argv[]) {
    pthread_t encrypter;
    pthread_t *decrypters;

    char* password;
    srand(time(NULL));
    parse_arguments(argc, argv);

    // Allocate global encrypted buffer
    g_encrypted_data.encrypted = malloc(g_password_length);
    if (!g_encrypted_data.encrypted) {
        fprintf(stderr, "Failed to allocate global encrypted buffer\n");
        return EXIT_FAILURE;
    }

    // Allocate decrypter threads array
    decrypters = malloc(sizeof(pthread_t) * g_num_decrypters);
    if (!decrypters) {
        fprintf(stderr, "Failed to allocate thread array\n");
        free(g_encrypted_data.encrypted);
        return EXIT_FAILURE;
    }

    pthread_create(&encrypter, NULL, encrypter_thread, NULL);

    for (int i = 0; i < g_num_decrypters; ++i) {
        pthread_create(&decrypters[i], NULL, decrypter_thread, NULL);
    }

    pthread_join(encrypter, NULL);
    for (int i = 0; i < g_num_decrypters; ++i) {
        pthread_join(decrypters[i], NULL);
    }

    free(g_encrypted_data.encrypted);
    free(decrypters);

    return 0;
}
