// linked_list.h
#ifndef LINKED_LIST_H
#define LINKED_LIST_H



typedef struct Node {
    int id;
    int fd;
    struct Node* next;
} Node;

typedef struct List{
    Node* head;
    Node* tail;
} List;

// פעולות על הרשימה
Node* create_node(int i_id, int i_fd);
List create_list();
void append(List* list, int i_id, int i_fd);
void free_list(Node* head);

#endif