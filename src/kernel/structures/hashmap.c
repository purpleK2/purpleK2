#include "hashmap.h"
#include "stdio.h"

#include <memory/heap/kheap.h>

#include <string.h>

#define HASHMAP_COMPARE(a, b)                                                  \
    ((hashmap->type == HASHMAP_INT) ? (a == b) : (!strncmp(a, b, 256)))
#define HASHMAP_COPY(a) ((hashmap->type == HASHMAP_INT) ? a : strdup(a))
#define HASHMAP_HASH(a)                                                        \
    ((hashmap->type == HASHMAP_INT) ? (unsigned long)a : hashmap_hash(a))
#define HASHMAP_FREE(a) ((hashmap->type == HASHMAP_INT) ? 0 : kfree(a))

unsigned long hashmap_hash(char *key) {
    unsigned long hash = 0;
    int c;

    while (key && (c = *key++)) {
        hash = c + (hash << 6) + (hash << 16) - hash;
    }

    return hash;
}

hashmap_t *hashmap_create(char *name, size_t size) {
    hashmap_t *map = kmalloc(sizeof(hashmap_t));
    map->name      = name;
    map->type      = HASHMAP_PTR;
    map->size      = size;
    map->entries   = kmalloc(sizeof(hashmap_node_t *) *
                             size); // Every entry is allocated separately. We're
                                    // instead allocating pointers.
    memset(map->entries, 0, sizeof(hashmap_node_t *) * size);

    return map;
}

hashmap_t *hashmap_create_int(char *name, size_t size) {
    hashmap_t *map = kmalloc(sizeof(hashmap_t));
    map->name      = name;
    map->type      = HASHMAP_INT;
    map->size      = size;
    map->entries   = kmalloc(sizeof(hashmap_node_t *) *
                             size); // Every entry is allocated separately. We're
                                    // instead allocating pointers.
    memset(map->entries, 0, sizeof(hashmap_node_t *) * size);

    return map;
}

void hashmap_set(hashmap_t *hashmap, void *key, void *value) {
    if (!hashmap)
        return;

    // Hash the key and get the entry
    unsigned long hash = (HASHMAP_HASH(key)) % hashmap->size;

    kprintf("[DEBUG] inserting key=%s hash=%lu\n", (char *)key, hash);
    hashmap_node_t *entry = hashmap->entries[hash];

    // Check if it's NULL - if it is allocate.
    if (entry == NULL) {
        // Allocate a new node
        hashmap_node_t *node   = kmalloc(sizeof(hashmap_node_t));
        node->key              = HASHMAP_COPY(key); // !!!: desperate refining
        node->value            = value;
        node->next             = NULL;
        hashmap->entries[hash] = node;
    } else {
        // Start iterating through a list of hashmap entries.
        // We'll check if one has the same key as specified, if so update it.
        hashmap_node_t *last_node = NULL;
        do {
            // Check if the current entry's key is the same
            if (HASHMAP_COMPARE(entry->key, key)) {
                // This is an entry with the same key. Set the new value.
                entry->value = value;
                return;
            } else {
                // Next node
                last_node = entry;
                entry     = entry->next;
            }
        } while (entry);

        // Done, we came to the last entry in the chain. Tack this one on.
        hashmap_node_t *node = kmalloc(sizeof(hashmap_node_t));
        node->key            = HASHMAP_COPY(key);
        node->value          = value;
        node->next           = NULL;
        last_node->next      = node;
    }
}

void *hashmap_get(hashmap_t *hashmap, void *key) {
    // Find the start of the chain.
    unsigned long hash = HASHMAP_HASH(key) % hashmap->size;
    kprintf("[DEBUG] getting key=%s hash=%lu\n", (char *)key, hash);
    hashmap_node_t *entry = hashmap->entries[hash];

    while (entry != NULL) {
        // Find the entry we need
        if (HASHMAP_COMPARE(entry->key, key)) {
            // Found it!
            return entry->value;
        }

        entry = entry->next;
    }

    // Nothing.
    return NULL;
}

void *hashmap_remove(hashmap_t *hashmap, void *key) {
    // Find the start of the chain.
    unsigned long hash    = HASHMAP_HASH(key) % hashmap->size;
    hashmap_node_t *entry = hashmap->entries[hash];

    if (entry) {
        if (HASHMAP_COMPARE(entry->key, key)) {
            // This is the node at the start of the chain. Remove it and use the
            // one in front of it.
            hashmap->entries[hash] = entry->next;
            void *output           = entry->value; // Return value
            HASHMAP_FREE(entry->key);
            kfree(entry);
            return output;
        } else {
            // Now we have to iterate through each one, find the one before it
            // and patch the chain.
            hashmap_node_t *last_node = NULL;
            do {
                if (HASHMAP_COMPARE(entry->key, key)) {
                    // Found the entry. Patch the chain first.
                    last_node->next = entry->next;

                    // Free values
                    void *output = entry->value;
                    HASHMAP_FREE(entry->key);
                    kfree(entry);
                    return output;
                } else {
                    last_node = entry;
                    entry     = entry->next;
                }
            } while (entry);
        }
    }

    // Nothing
    return NULL;
}

int hashmap_has(hashmap_t *hashmap, void *key) {
    // NOTE: We can't just call hashmap_get because the value could be NULL.

    // Find the start of the chain.
    unsigned long hash    = HASHMAP_HASH(key) % hashmap->size;
    hashmap_node_t *entry = hashmap->entries[hash];

    while (entry != NULL) {
        // Find the entry we need
        if (HASHMAP_COMPARE(entry->key, key)) {
            // Found it!
            return 1;
        }

        entry = entry->next;
    }

    return 0;
}

list_t *hashmap_keys(hashmap_t *hashmap) {
    list_t *ret = list_create("keys");
    for (uint32_t i = 0; i < hashmap->size; i++) {
        hashmap_node_t *node = hashmap->entries[i];
        while (node) {
            list_append(ret, node->key);
            node = node->next;
        }
    }
    return ret;
}

list_t *hashmap_values(hashmap_t *hashmap) {
    list_t *ret = list_create("vals");
    for (uint32_t i = 0; i < hashmap->size; i++) {
        hashmap_node_t *node = hashmap->entries[i];
        while (node) {
            list_append(ret, node->value);
            node = node->next;
        }
    }
    return ret;
}

void hashmap_free(hashmap_t *hashmap) {
    for (uint32_t i = 0; i < hashmap->size; i++) {
        hashmap_node_t *node = hashmap->entries[i];
        while (node) {
            // We're about to free the node, store it.
            hashmap_node_t *temp = node;
            node                 = node->next;

            // Now free it.
            HASHMAP_FREE(temp->key);
            kfree(temp);
        }
    }

    // Free the entry map
    kfree(hashmap->entries);
}