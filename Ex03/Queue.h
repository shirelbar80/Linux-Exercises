#ifndef QUEUE_H
#define QUEUE_H
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    int thread_id;//ID of the decrypter thread
    char* decryptedPassword;
} SharedPasswordData;

// Define the structure for a node of the linked list
typedef struct Node {
    SharedPasswordData data;
    struct Node* next;
} node;

// Define the structure for the queue
typedef struct Queue {
    node* front;
    node* back;
} queue;

// Function declarations
node* createNode(SharedPasswordData data);
queue* createQueue();
int isEmpty(queue* q);
void enqueue(queue* q, SharedPasswordData data);
SharedPasswordData dequeue(queue* q);
void queue_clear(queue* q);


#endif // QUEUE_H
