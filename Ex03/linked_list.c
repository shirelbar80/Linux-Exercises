#include <stdio.h>
#include <stdlib.h>
#include "linked_list.h"

List create_list(){
    
    List lst;
    
    lst.head = NULL;
    lst.tail = NULL;
    
    return lst;
}

Node* create_node(int i_id, int i_fd) {
    Node* new_node = (Node*)malloc(sizeof(Node));
    if (!new_node) {
        perror("Memory allocation failed");
        exit(EXIT_FAILURE);
    }
    new_node->id = i_id;
    new_node->fd = i_fd;
    new_node->next = NULL;
    return new_node;
}

void append(List* list, int i_id, int i_fd){
    Node* new_node = create_node(i_id, i_fd);

    if (list->head == NULL) {
        list->head = list->tail = new_node;
        return;
    }

    new_node->next = list->tail;
    list->tail = new_node;
}



void free_list(Node* head) {
    Node* current = head;
    while (current != NULL) {
        Node* next = current->next;
        free(current);
        current = next;
    }
}