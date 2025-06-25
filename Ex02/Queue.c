#include "Queue.h"

// Function to create a new node
node* createNode(SharedPasswordData data)
{
    // Allocate memory for a new node
    node* newNode = (node*)malloc(sizeof(node));
    // Check if memory allocation was successful
    if (newNode == NULL)
        return NULL;
    // Initialize the node's data and next pointer
    newNode->data = data;
    newNode->next = NULL;
    return newNode;
}

// Function to create a new queue
queue* createQueue()
{
    // Allocate memory for a new queue
    queue* newQueue = (queue*)malloc(sizeof(queue));
    // Initialize the front and back pointers of the queue
    newQueue->front = newQueue->back = NULL;
    return newQueue;
}

// Function to check if the queue is empty
int isEmpty(queue* q)
{
    // Check if the front pointer is NULL
    return q->front == NULL;
}

// Function to add an element to the queue
void enqueue(queue* q, SharedPasswordData data)
{
    // Create a new node with the given data
    node* newNode = createNode(data);
    // Check if memory allocation for the new node was
    // successful
    if (!newNode) {
        printf("Queue Overflow!\n");
        return;
    }
    // If the queue is empty, set the front and back
    // pointers to the new node
    if (q->back == NULL) {
        q->front = q->back = newNode;
        return;
    }
    // Add the new node at the end of the queue and update
    // the back pointer
    q->back->next = newNode;
    q->back = newNode;
}

// Function to remove an element from the queue
SharedPasswordData dequeue(queue* q)
{
    // Check if the queue is empty
    if (isEmpty(q)) {
        printf("Queue Underflow\n");
        SharedPasswordData temp;
        temp.thread_id = 0;
        temp.decryptedPassword = NULL;
        return temp; // Return a default value if empty
    }
    // Store the front node and update the front pointer
    node* temp = q->front;
    q->front = q->front->next;
    // If the queue becomes empty, update the back pointer
    if (q->front == NULL)
        q->back = NULL;
    // Store the data of the front node and free its memory
    SharedPasswordData data = temp->data;
    free(temp);
    return data;
}




