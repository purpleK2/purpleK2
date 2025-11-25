#ifndef HASHMAP_H
#define HASHMAP_H

#include <stddef.h>

#include <structures/list.h>

#define HASHMAP_PTR 0
#define HASHMAP_INT 1

typedef struct _hashmap_node {
    char *key;
    void *value;
    struct _hashmap_node *next;
} hashmap_node_t;

typedef struct _hashmap {
    int type;
    char *name;
    size_t size;
    hashmap_node_t **entries;
} hashmap_t;

hashmap_t *hashmap_create(char *name, size_t size);
hashmap_t *hashmap_create_int(char *name, size_t size);
void hashmap_set(hashmap_t *hashmap, void *key, void *value);
void *hashmap_get(hashmap_t *hashmap, void *key);
void *hashmap_remove(hashmap_t *hashmap, void *key);
int hashmap_has(hashmap_t *hashmap, void *key);
list_t *hashmap_keys(hashmap_t *hashmap);
list_t *hashmap_values(hashmap_t *hashmap);
void hashmap_free(hashmap_t *hashmap);

#endif // HASHMAP_H
