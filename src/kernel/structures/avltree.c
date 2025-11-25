#include "avltree.h"
#include <memory/heap/kheap.h>
#include <util/string.h>

// Helper function to get the maximum of two integers
static int max(int a, int b) {
    return (a > b) ? a : b;
}

// Get the height of a node, or -1 if node is NULL
static int get_height(AVLNode *node) {
    return node ? node->height : -1;
}

// Calculate the balance factor of a node
static int get_balance_factor(AVLNode *node) {
    if (!node)
        return 0;
    return get_height(node->left) - get_height(node->right);
}

// Right rotation
static AVLNode *right_rotate(AVLNode *y) {
    AVLNode *x  = y->left;
    AVLNode *T2 = x->right;

    // Perform rotation
    x->right = y;
    y->left  = T2;

    // Update parent pointers
    x->parent = y->parent;
    y->parent = x;
    if (T2)
        T2->parent = y;

    // Update heights
    y->height = 1 + max(get_height(y->left), get_height(y->right));
    x->height = 1 + max(get_height(x->left), get_height(x->right));

    return x;
}

// Left rotation
static AVLNode *left_rotate(AVLNode *x) {
    AVLNode *y  = x->right;
    AVLNode *T2 = y->left;

    // Perform rotation
    y->left  = x;
    x->right = T2;

    // Update parent pointers
    y->parent = x->parent;
    x->parent = y;
    if (T2)
        T2->parent = x;

    // Update heights
    x->height = 1 + max(get_height(x->left), get_height(x->right));
    y->height = 1 + max(get_height(y->left), get_height(y->right));

    return y;
}

// Create a new AVL tree
AVLTree *avl_create(AVLComparator compare) {
    AVLTree *tree = kmalloc(sizeof(AVLTree));
    if (!tree)
        return NULL;

    tree->root    = NULL;
    tree->compare = compare;
    return tree;
}

// Recursive function to free all nodes
static void free_node(AVLNode *node) {
    if (!node)
        return;
    free_node(node->left);
    free_node(node->right);
    kfree(node);
}

// Destroy the entire AVL tree
void avl_destroy(AVLTree *tree) {
    if (!tree)
        return;
    free_node(tree->root);
    kfree(tree);
}

// Internal insert function
static AVLNode *insert_node(AVLTree *tree, AVLNode *node, void *key,
                            void *value, AVLNode *parent) {
    // 1. Perform standard BST insertion
    if (!node) {
        AVLNode *new_node = kmalloc(sizeof(AVLNode));
        if (!new_node)
            return NULL;

        new_node->key    = key;
        new_node->value  = value;
        new_node->height = 1;
        new_node->left   = NULL;
        new_node->right  = NULL;
        new_node->parent = parent;
        return new_node;
    }

    // Compare and insert
    int compare_result = tree->compare(key, node->key);
    if (compare_result < 0) {
        node->left = insert_node(tree, node->left, key, value, node);
    } else if (compare_result > 0) {
        node->right = insert_node(tree, node->right, key, value, node);
    } else {
        // Duplicate key, return original node
        return node;
    }

    // 2. Update height of current node
    node->height = 1 + max(get_height(node->left), get_height(node->right));

    // 3. Get the balance factor to check if this node became unbalanced
    int balance = get_balance_factor(node);

    // 4. If unbalanced, there are 4 cases

    // Left Left Case
    if (balance > 1 && tree->compare(key, node->left->key) < 0)
        return right_rotate(node);

    // Right Right Case
    if (balance < -1 && tree->compare(key, node->right->key) > 0)
        return left_rotate(node);

    // Left Right Case
    if (balance > 1 && tree->compare(key, node->left->key) > 0) {
        node->left = left_rotate(node->left);
        return right_rotate(node);
    }

    // Right Left Case
    if (balance < -1 && tree->compare(key, node->right->key) < 0) {
        node->right = right_rotate(node->right);
        return left_rotate(node);
    }

    // Node didn't change
    return node;
}

// Public insert function
int avl_insert(AVLTree *tree, void *key, void *value) {
    if (!tree)
        return -1;

    // If tree is empty
    if (!tree->root) {
        tree->root = insert_node(tree, tree->root, key, value, NULL);
        return tree->root ? 0 : -1;
    }

    // Perform insertion
    AVLNode *new_root = insert_node(tree, tree->root, key, value, NULL);

    // Update root if it changed due to rotations
    if (new_root != tree->root) {
        tree->root = new_root;
    }

    return 0;
}

// Find a node with a given key
static AVLNode *find_node(AVLTree *tree, void *key) {
    if (!tree || !tree->root)
        return NULL;

    AVLNode *current = tree->root;
    while (current) {
        int compare_result = tree->compare(key, current->key);
        if (compare_result == 0)
            return current;
        current = (compare_result < 0) ? current->left : current->right;
    }
    return NULL;
}

// Find value for a given key
void *avl_find(AVLTree *tree, void *key) {
    AVLNode *node = find_node(tree, key);
    return node ? node->value : NULL;
}

// Find minimum value node
static AVLNode *find_min(AVLNode *node) {
    AVLNode *current = node;
    while (current && current->left) {
        current = current->left;
    }
    return current;
}

// Internal remove function
static AVLNode *remove_node(AVLTree *tree, AVLNode *root, void *key) {
    // Standard BST deletion
    if (!root)
        return NULL;

    int compare_result = tree->compare(key, root->key);
    if (compare_result < 0)
        root->left = remove_node(tree, root->left, key);
    else if (compare_result > 0)
        root->right = remove_node(tree, root->right, key);
    else {
        // Node with the key to be deleted found

        // Node with only one child or no child
        if (!root->left || !root->right) {
            AVLNode *temp = root->left ? root->left : root->right;

            // No child case
            if (!temp) {
                temp = root;
                root = NULL;
            } else { // One child case
                // Copy the contents of the non-empty child
                *root = *temp;
            }
            kfree(temp);
        } else {
            // Node with two children: Get the inorder successor
            AVLNode *temp = find_min(root->right);

            // Copy the inorder successor's data to this node
            root->key   = temp->key;
            root->value = temp->value;

            // Delete the inorder successor
            root->right = remove_node(tree, root->right, temp->key);
        }
    }

    // If the tree had only one node, return
    if (!root)
        return NULL;

    // Update height of current node
    root->height = 1 + max(get_height(root->left), get_height(root->right));

    // Get balance factor
    int balance = get_balance_factor(root);

    // Balance the tree

    // Left Left Case
    if (balance > 1 && get_balance_factor(root->left) >= 0)
        return right_rotate(root);

    // Left Right Case
    if (balance > 1 && get_balance_factor(root->left) < 0) {
        root->left = left_rotate(root->left);
        return right_rotate(root);
    }

    // Right Right Case
    if (balance < -1 && get_balance_factor(root->right) <= 0)
        return left_rotate(root);

    // Right Left Case
    if (balance < -1 && get_balance_factor(root->right) > 0) {
        root->right = right_rotate(root->right);
        return left_rotate(root);
    }

    return root;
}

// Public remove function
int avl_remove(AVLTree *tree, void *key) {
    if (!tree || !tree->root)
        return -1;

    AVLNode *new_root = remove_node(tree, tree->root, key);

    // Update root if it changed
    if (new_root != tree->root) {
        tree->root = new_root;
    }

    return 0;
}

// Inorder traversal
static void inorder_recursive(AVLNode *node, AVLVisitor visitor) {
    if (!node)
        return;

    inorder_recursive(node->left, visitor);
    visitor(node->key, node->value);
    inorder_recursive(node->right, visitor);
}

void avl_traverse_inorder(AVLTree *tree, AVLVisitor visitor) {
    if (!tree || !visitor)
        return;
    inorder_recursive(tree->root, visitor);
}

// Find first (leftmost) node
AVLNode *avl_first(AVLTree *tree) {
    if (!tree || !tree->root)
        return NULL;

    AVLNode *current = tree->root;
    while (current->left) {
        current = current->left;
    }
    return current;
}

// Find next node in inorder traversal
AVLNode *avl_next(AVLNode *node) {
    if (!node)
        return NULL;

    // If right subtree exists, find leftmost node in right subtree
    if (node->right) {
        AVLNode *current = node->right;
        while (current->left) {
            current = current->left;
        }
        return current;
    }

    // Otherwise, go up until we find a node that is a left child
    AVLNode *current = node;
    while (current->parent && current == current->parent->right) {
        current = current->parent;
    }

    return current->parent;
}

// Get value of a node
void *avl_node_value(AVLNode *node) {
    return node ? node->value : NULL;
}