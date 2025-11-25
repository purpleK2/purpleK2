#ifndef AVL_TREE_H
#define AVL_TREE_H

#include <stddef.h>

typedef int (*AVLComparator)(const void *a, const void *b);
typedef void (*AVLVisitor)(void *key, void *value);

typedef struct AVLNode {
    void *key;
    void *value;
    int height;
    struct AVLNode *left;
    struct AVLNode *right;
    struct AVLNode *parent;
} AVLNode;

typedef struct AVLTree {
    AVLNode *root;
    AVLComparator compare;
} AVLTree;

AVLTree *avl_create(AVLComparator compare);
void avl_destroy(AVLTree *tree);

int avl_insert(AVLTree *tree, void *key, void *value);
int avl_remove(AVLTree *tree, void *key);
void *avl_find(AVLTree *tree, void *key);

void avl_traverse_inorder(AVLTree *tree, AVLVisitor visitor);

AVLNode *avl_first(AVLTree *tree);
AVLNode *avl_next(AVLNode *node);
void *avl_node_value(AVLNode *node);

#endif