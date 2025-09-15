#ifndef LIST_H
#define LIST_H

#include <stdbool.h>
#include <stddef.h>

typedef struct _node {
    struct _node *next;
    struct _node *prev;
    void *value;
    void *owner;
} node_t;

typedef struct _list {
    char *name;
    node_t *head;
    node_t *tail;
    size_t length;
} list_t;

#define foreach(i, list) for (node_t *i = list->head; i != NULL; i = i->next)

list_t *list_create(char *name);
void list_destroy(list_t *list, bool free_values);
void list_append(list_t *list, void *item);
void list_append_after(list_t *list, node_t *append_to, void *item);
void list_append_before(list_t *list, node_t *append_before, void *item);
void list_append_node(list_t *list, node_t *node);
void list_append_node_after(list_t *list, node_t *append_to, node_t *node);
void list_append_node_before(list_t *list, node_t *append_before, node_t *node);
node_t *list_find(list_t *list, void *item);
void list_delete(list_t *list, node_t *node);
void list_delete_index(list_t *list, size_t index);
node_t *list_pop(list_t *list);
node_t *list_popleft(list_t *list);

#endif // LIST_H