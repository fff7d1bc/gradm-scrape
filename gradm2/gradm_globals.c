#include "gradm.h"

struct glob_file *glob_files_head;
struct glob_file *glob_files_tail;
struct symlink *symlinks;
struct deleted_file *deleted_files;
struct role_acl *current_role;
struct proc_acl *current_subject;
char *current_acl_file;

int is_24_kernel;

uid_t special_role_uid;

u_int32_t num_subjects;
u_int32_t num_roles;
u_int32_t num_objects;
u_int32_t num_pointers;
u_int32_t num_domain_children;

char *current_learn_rolename;
char *current_learn_subject;
u_int16_t current_learn_rolemode;

char **dont_reduce_dirs;
char **always_reduce_dirs;
char **protected_paths;
char **read_protected_paths;
char **high_reduce_dirs;
char **high_protected_paths;
u_int32_t grlearn_options;
