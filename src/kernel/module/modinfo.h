#ifndef MODINFO_H
#define MODINFO_H

typedef enum _emodpriority {
    MOD_PRIO_LOW      = 1,
    MOD_PRIO_MEDIUM   = 2,
    MOD_PRIO_HIGH     = 3,
    MOD_PRIO_HIGHEST  = 4,
    MOD_PRIO_CRITICAL = 5,
} mod_priority_t;

typedef struct _modinfo {
    char *name;
    char *version;
    char *author;
    char *license;
    char *description;
    char *url;
    mod_priority_t priority;
    char *deps[]; // an array of names so like module fat32 requires module fs
                  // to be loaded
} modinfo_t;

#endif // MODINFO_H