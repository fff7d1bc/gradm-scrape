#ifndef __GRADM_FUNC_H
#define __GRADM_FUNC_H

void yyerror(const char *s);
FILE *open_acl_file(const char *filename);
void get_user_passwd(struct gr_pw_entry *entry, int mode);
int transmit_to_kernel(struct gr_arg_wrapper *buf);
void generate_salt(struct gr_pw_entry *entry);
void write_user_passwd(struct gr_pw_entry *entry);
void parse_acls(void);
void analyze_acls(void);
void generate_hash(struct gr_pw_entry *entry);
void init_variables(void);
void parse_args(int argc, char *argv[]);
gr_cap_t cap_conv(const char *cap);
gr_cap_t cap_drop(gr_cap_t a, gr_cap_t b);
gr_cap_t cap_combine(gr_cap_t a, gr_cap_t b);
gr_cap_t cap_intersect(gr_cap_t a, gr_cap_t b);
int cap_same(gr_cap_t a, gr_cap_t b);
gr_cap_t cap_invert(gr_cap_t a);
int cap_isclear(gr_cap_t a);
u_int32_t file_mode_conv(const char *mode);
u_int32_t proc_subject_mode_conv(const char *mode);
u_int32_t proc_object_mode_conv(const char *mode);
int add_proc_subject_acl(struct role_acl *role, char *filename, u_int32_t mode, int flag);
int add_proc_object_acl(struct proc_acl *subject, char *filename,
			u_int32_t mode, int type);
void add_cap_acl(struct proc_acl *subject, const char *cap, const char *audit);
void add_paxflag_acl(struct proc_acl *subject, const char *paxflag);
void add_gradm_acl(struct role_acl *role);
void add_gradm_pam_acl(struct role_acl *role);
void add_grlearn_acl(struct role_acl *role);
void add_domain_child(struct role_acl *role, char *idname);
void change_current_acl_file(const char *filename);
struct gr_arg_wrapper *conv_user_to_kernel(struct gr_pw_entry *entry);
int parent_dir(const char *filename, char *parent_dirent[]);
void rem_proc_object_acl(struct proc_acl *proc, struct file_acl *filp);
void expand_acls(void);
int test_perm(const char *obj, const char *subj);
void add_res_acl(struct proc_acl *subject, const char *name,
		 const char *soft, const char *hard);
void pass_struct_to_human(FILE * stream);
int is_valid_elf_binary(const char *filename);
void handle_learn_logs(FILE *logfile, FILE * stream);
void modify_caps(struct proc_acl *proc, int cap);
void modify_res(struct proc_acl *proc, int res, unsigned long cur,
		unsigned long max);
void add_ip_acl(struct proc_acl *subject, u_int8_t mode, struct ip_acl *tmp);
void add_host_acl(struct proc_acl *subject, u_int8_t mode, char *host, struct ip_acl *tmp);
int read_saltandpass(unsigned char *rolename, unsigned char *salt, unsigned char *pass);
void add_kernel_acl(void);
int add_role_acl(struct role_acl **role, char *rolename, u_int16_t type,
		 int ignore);
u_int16_t role_mode_conv(const char *mode);
u_int32_t get_ip(char *p);
void conv_name_to_type(struct ip_acl *ip, char *name);
void add_role_allowed_ip(struct role_acl *role, u_int32_t addr, u_int32_t netmask);
void add_role_allowed_host(struct role_acl *role, char *host, u_int32_t netmask);
void add_role_transition(struct role_acl *role, char *rolename);
void add_id_transition(struct proc_acl *subject, char *idname, int usergroup, int allowdeny);
void add_proc_nested_acl(struct role_acl *role, char *mainsubjname, char **nestednames, int nestlen, u_int32_t nestmode);
void start_grlearn(char *logfile);
void stop_grlearn(void);
void sym_store(char *symname, struct var_object *object);
struct var_object *sym_retrieve(char *symname);
void add_var_object(struct var_object **object, char *name, u_int32_t mode);
void interpret_variable(struct var_object *var);
struct var_object *union_objects(struct var_object *var1, struct var_object *var2);
struct var_object *intersect_objects(struct var_object *var1, struct var_object *var2);
struct var_object *differentiate_objects(struct var_object *var1, struct var_object *var2);
void sort_file_list(struct gr_hash_struct *hash);
struct gr_learn_file_node *match_file_node(struct gr_learn_file_node *base, const char *filename);
struct gr_learn_file_tmp_node *conv_filename_to_struct(char *filename, u_int32_t mode);
void match_role(struct gr_learn_group_node *grouplist, uid_t uid, gid_t gid, struct gr_learn_group_node **group, struct gr_learn_user_node **user);
struct gr_learn_ip_node * find_insert_ip(struct gr_learn_ip_node **base, u_int32_t ip);
void conv_mode_to_str(u_int32_t mode, char *modestr, unsigned short len);
void conv_subj_mode_to_str(u_int32_t mode, char *modestr, unsigned short len);
void generate_full_learned_acls(FILE *learn_log, FILE *stream);
void reduce_roles(struct gr_learn_group_node **grouplist);
void insert_file(struct gr_learn_file_node **base, char *filename, u_int32_t mode, u_int8_t subj);
void first_stage_reduce_tree(struct gr_learn_file_node *base);
void second_stage_reduce_tree(struct gr_learn_file_node *base);
void third_stage_reduce_tree(struct gr_learn_file_node *base);
void traverse_roles(struct gr_learn_group_node *grouplist,
		int (*act)(struct gr_learn_group_node *group, struct gr_learn_user_node *user, FILE *stream),
		FILE *stream);
void traverse_file_tree(struct gr_learn_file_node *base,
		int (*act)(struct gr_learn_file_node *node, struct gr_learn_file_node *optarg, FILE *stream),
		struct gr_learn_file_node *optarg, FILE *stream);
void reduce_ip_tree(struct gr_learn_ip_node *base);
void reduce_ports_tree(struct gr_learn_ip_node *base);
void display_roles(struct gr_learn_group_node *grouplist, FILE *stream);
void add_fulllearn_acl(void);
void insert_ip(struct gr_learn_ip_node **base, u_int32_t ip, u_int16_t port, u_int8_t proto,
		u_int8_t socktype);
int is_globbed_file(char *filename);
int match_filename(char *filename, char *pattern, unsigned int len, int is_glob);
int is_protected_path(char *filename, u_int32_t mode);
int is_read_protected_path(char *filename, u_int32_t mode);
int is_write_protected_path(char *filename, u_int32_t mode);

void add_grlearn_option(u_int32_t option);
struct gr_learn_role_entry *
insert_learn_role(struct gr_learn_role_entry **role_list, char *rolename, u_int16_t rolemode);
void insert_learn_object(struct gr_learn_file_node *subject, struct gr_learn_file_tmp_node *object);
void insert_learn_role_subject(struct gr_learn_role_entry *role, struct gr_learn_file_tmp_node *subject);
void insert_learn_group_subject(struct gr_learn_group_node *role, struct gr_learn_file_tmp_node *subject);
void insert_learn_user_subject(struct gr_learn_user_node *role, struct gr_learn_file_tmp_node *subject);
struct gr_learn_role_entry *
find_learn_role(struct gr_learn_role_entry *role_list, char *rolename);
int full_reduce_object_node(struct gr_learn_file_node *subject,
			    struct gr_learn_file_node *unused1,
			    FILE *unused2);
void
conv_role_mode_to_str(u_int16_t mode, char *modestr, unsigned short len);
int full_reduce_ip_node(struct gr_learn_file_node *subject,
			struct gr_learn_file_node *unused1,
			FILE *unused2);
void display_ip_tree(struct gr_learn_ip_node *base, u_int8_t contype, FILE *stream);
int display_only_ip(struct gr_learn_ip_node *node, struct gr_learn_ip_node **unused, u_int8_t unused2,
		    FILE *stream);
void traverse_ip_tree(struct gr_learn_ip_node *base,
			struct gr_learn_ip_node **optarg,
			int (*act)(struct gr_learn_ip_node *node, struct gr_learn_ip_node **optarg, u_int8_t contype, FILE *stream),
			u_int8_t contype, FILE *stream);
void display_tree(struct gr_learn_file_node *base, FILE *stream);
void enforce_high_protected_paths(struct gr_learn_file_node *subject);
void insert_user(struct gr_learn_group_node **grouplist, char *username, char *groupname, uid_t uid, gid_t gid);
void add_rolelearn_acl(void);
int ensure_subject_security(struct gr_learn_file_node *subject,
			struct gr_learn_file_node *unused1,
			FILE *unused2);

void check_acl_status(u_int16_t reqmode);
struct file_acl *lookup_acl_object_by_name(struct proc_acl *subject, char *name);
struct proc_acl *lookup_acl_subject_by_name(struct role_acl *role, char *name);
struct file_acl *lookup_acl_object(struct proc_acl *subject, struct file_acl *object);
struct proc_acl *lookup_acl_subject(struct role_acl *role, struct proc_acl *subject);

void * gr_dyn_alloc(unsigned long len);
void * gr_stat_alloc(unsigned long len);
void * gr_dyn_realloc(void *addr, unsigned long len);
void gr_dyn_free(void *addr);
void gr_stat_free(void *addr);
char * gr_strdup(char *str);

void insert_acl_object(struct proc_acl *subject, struct file_acl *object);
void insert_acl_subject(struct role_acl *role, struct proc_acl *subject);

void insert_nested_acl_subject(struct proc_acl *subject);

char *gr_get_user_name(uid_t uid);
char *gr_get_group_name(gid_t gid);

void output_role_info(struct gr_learn_group_node *group, struct gr_learn_user_node *user, FILE *stream);
void output_learn_header(FILE *stream);

int display_leaf(struct gr_learn_file_node *node, struct gr_learn_file_node *unused1, FILE *stream);

void insert_learn_id_transition(unsigned int ***list, int real, int eff, int fs);
void add_to_string_array(char ***array, char *str);
void parse_learn_config(void);

void check_pam_auth(unsigned char *rolename);

void add_replace_string(char *name, char *replacewith);
char *lookup_replace_string(char *name);
char *process_string_replace(char *str);

void sort_file_node_list(struct gr_learn_file_node *root);

void add_sock_family(struct proc_acl *subject, char *family);
char *get_sock_family_from_val(int val);

#ifdef GRADM_DEBUG
void check_file_node_list_integrity(struct gr_learn_file_node **filelist);
void check_conformity_with_learned_rules(struct gr_learn_file_node *subject);
void check_high_protected_path_enforcement(struct gr_learn_file_node *subject);
#endif

#endif
