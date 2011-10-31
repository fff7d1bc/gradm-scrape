#include "gradm.h"

extern struct gr_learn_file_node **cachednode;
extern unsigned int cachedlen;

struct gr_learn_group_node **role_list = NULL;
extern FILE *fulllearn_pass1in;
extern FILE *fulllearn_pass2in;
extern FILE *fulllearn_pass3in;
extern int fulllearn_pass1parse(void);
extern int fulllearn_pass2parse(void);
extern int fulllearn_pass3parse(void);

void fulllearn_pass1(FILE *stream)
{
	fulllearn_pass1in = stream;
	printf("Beginning full learning 1st pass...");
	fflush(stdout);
	fulllearn_pass1parse();
	printf("done.\n");
	fflush(stdout);
	printf("Beginning full learning role reduction...");
	fflush(stdout);
	reduce_roles(&role_list);
	printf("done.\n");
	fflush(stdout);

	return;
}

int full_reduce_subjects(struct gr_learn_group_node *group,
			 struct gr_learn_user_node *user, FILE *unused)
{
	struct gr_learn_file_tmp_node **tmptable;
	unsigned long i;
	u_int32_t table_size;

	if (user) {
		printf("Beginning full learning subject reduction for user %s...", user->rolename);
		fflush(stdout);
		if (!user->hash)
			insert_file(&(user->subject_list), "/", GR_PROCFIND, 1);
		else {
			sort_file_list(user->hash);
			tmptable = (struct gr_learn_file_tmp_node **)user->hash->table;
			table_size = user->hash->table_size;
			for (i = 0; i < table_size; i++) {
				if (tmptable[i] == NULL)
					continue;
				insert_file(&(user->subject_list), tmptable[i]->filename, tmptable[i]->mode, 1);
			}
		}
		printf("done.\n");
		fflush(stdout);
	} else {
		printf("Beginning full learning subject reduction for group %s...", group->rolename);
		fflush(stdout);
		if (!group->hash)
			insert_file(&(group->subject_list), "/", GR_PROCFIND, 1);
		else {
			sort_file_list(group->hash);
			tmptable = (struct gr_learn_file_tmp_node **)group->hash->table;
			table_size = group->hash->table_size;
			for (i = 0; i < table_size; i++) {
				if (tmptable[i] == NULL)
					continue;
				insert_file(&(group->subject_list), tmptable[i]->filename, tmptable[i]->mode, 1);
			}
		}
		printf("done.\n");
		fflush(stdout);
	}

	return 0;
}

int full_reduce_allowed_ips(struct gr_learn_group_node *group,
			    struct gr_learn_user_node *user,
			    FILE *unused)
{
	if (user)
		reduce_ip_tree(user->allowed_ips);
	else if (group)
		reduce_ip_tree(group->allowed_ips);

	return 0;
}	

void fulllearn_pass2(FILE *stream)
{
	fulllearn_pass2in = stream;
	printf("Beginning full learning 2nd pass...");
	fflush(stdout);
	fulllearn_pass2parse();
	printf("done.\n");
	fflush(stdout);

	traverse_roles(role_list, &full_reduce_subjects, NULL);
	traverse_roles(role_list, &full_reduce_allowed_ips, NULL);

	return;
}

int full_reduce_object_node(struct gr_learn_file_node *subject,
			    struct gr_learn_file_node *unused1,
			    FILE *unused2)
{
	struct gr_learn_file_tmp_node **tmptable;
	unsigned long i;
	u_int32_t table_size;

	if (subject->hash == NULL)
		return 0;
	printf("Beginning full learning object reduction for subject %s...", subject->filename);
	fflush(stdout);
	sort_file_list(subject->hash);
	tmptable = (struct gr_learn_file_tmp_node **)subject->hash->table;
	table_size = subject->hash->table_size;
	for (i = 0; i < table_size; i++) {
		if (tmptable[i] == NULL)
			continue;
		insert_file(&(subject->object_list), tmptable[i]->filename, tmptable[i]->mode, 0);
	}

	first_stage_reduce_tree(subject->object_list);
	second_stage_reduce_tree(subject->object_list);

	enforce_high_protected_paths(subject);

	third_stage_reduce_tree(subject->object_list);

	printf("done.\n");
	fflush(stdout);
	return 0;
}

int full_reduce_ip_node(struct gr_learn_file_node *subject,
			struct gr_learn_file_node *unused1,
			FILE *unused2)
{
	struct gr_learn_ip_node *tmp = subject->connect_list;

	reduce_ip_tree(tmp);
	reduce_ports_tree(tmp);

	tmp = subject->bind_list;

	reduce_ip_tree(tmp);
	reduce_ports_tree(tmp);

	return 0;
}	

void free_subject_ids(unsigned int ***list, int thresh)
{
	unsigned int **p;
	unsigned int size;
	int i;

	size = 0;
	p = *list;

	if (p == NULL)
		return;
	while (*p) {
		p++;
		size++;
	}

	if (size > thresh) {
		for (i = 0; i < size; i++)
			free(*(*list + i));
		free(*list);
		*list = NULL;
	} else if (thresh == 0) {
		free(*list);
		*list = NULL;
	}

	return;
}

int full_reduce_id_node(struct gr_learn_file_node *subject,
			struct gr_learn_file_node *unused1,
			FILE *unused2)
{
	if (subject->subject == NULL ||
	    !cap_raised(subject->subject->cap_raise, CAP_SETUID))
		free_subject_ids(&(subject->user_trans_list), 0);
	else
		free_subject_ids(&(subject->user_trans_list), 3);

	if (subject->subject == NULL ||
	    !cap_raised(subject->subject->cap_raise, CAP_SETGID))
		free_subject_ids(&(subject->group_trans_list), 0);
	else
		free_subject_ids(&(subject->group_trans_list), 3);
	
	return 0;
}	

int full_reduce_ips(struct gr_learn_group_node *group,
			 struct gr_learn_user_node *user,
			FILE *unused)
{
	struct gr_learn_file_node *subjects;

	if (user)
		subjects = user->subject_list;
	else
		subjects = group->subject_list;

	traverse_file_tree(subjects, &full_reduce_ip_node, NULL, NULL);

	return 0;
}

void free_ip_ports(struct gr_learn_ip_node *node)
{
	struct gr_learn_ip_node **tmp;
	u_int16_t **tmp2;

	if (node == NULL)
		return;

	tmp = node->leaves;

	while (tmp && *tmp) {
		free_ip_ports(*tmp);
		tmp++;
	}
	
	if (node->leaves) {
		gr_dyn_free(node->leaves);
		node->leaves = NULL;
	}

	tmp2 = node->ports;
	while (tmp2 && *tmp2) {
		gr_stat_free(*tmp2);
		tmp2++;
	}

	if (node->ports)
		gr_dyn_free(node->ports);
	gr_stat_free(node);
	node = NULL;

	return;
}

void free_subject_objects(struct gr_learn_file_node *node)
{
	struct gr_learn_file_node **tmp;

	if (node == NULL)
		return;

	tmp = node->leaves;

	while (tmp && *tmp) {
		free_subject_objects(*tmp);
		tmp++;
	}

	if (node->leaves) {
		gr_dyn_free(node->leaves);
		node->leaves = NULL;
	}

	free_ip_ports(node->connect_list);
	free_ip_ports(node->bind_list);

	if (node->subject) {
		free(node->subject);
		node->subject = NULL;
	}
	free(node->filename);
	gr_stat_free(node);
	node = NULL;
	

	return;
}

void free_subject_full(struct gr_learn_file_node *subject)
{
	struct gr_learn_file_tmp_node **tmptable;
	unsigned long table_size, i;

	cachednode = NULL;
	cachedlen = 0;

	if (subject->hash) {
		tmptable = (struct gr_learn_file_tmp_node **)subject->hash->table;
		table_size = subject->hash->table_size;
		for (i = 0; i < table_size; i++) {
			if (tmptable[i] == NULL)
				continue;
			free(tmptable[i]->filename);
			free(tmptable[i]);
		}
		free(tmptable);
		free(subject->hash);
	}

	free_subject_ids(&(subject->user_trans_list), 0);
	free_subject_ids(&(subject->group_trans_list), 0);

	free_subject_objects(subject->object_list);

	return;
}

void free_role_user_full(struct gr_learn_user_node *user)
{
	struct gr_learn_file_tmp_node **tmptable;
	unsigned long table_size, i;

	if (user->hash) {
		tmptable = (struct gr_learn_file_tmp_node **)user->hash->table;
		table_size = user->hash->table_size;
		for (i = 0; i < table_size; i++) {
			if (tmptable[i] == NULL)
				continue;
			free(tmptable[i]->filename);
			free(tmptable[i]);
		}
		free(tmptable);
		free(user->hash);
	}

	free_subject_objects(user->subject_list);
	free_ip_ports(user->allowed_ips);

	return;
}

void free_role_group_full(struct gr_learn_group_node *group)
{
	struct gr_learn_file_tmp_node **tmptable;
	unsigned long table_size, i;

	if (group->hash) {
		tmptable = (struct gr_learn_file_tmp_node **)group->hash->table;
		table_size = group->hash->table_size;
		for (i = 0; i < table_size; i++) {
			if (tmptable[i] == NULL)
				continue;
			free(tmptable[i]->filename);
			free(tmptable[i]);
		}
		free(tmptable);
		free(group->hash);
	}

	free_subject_objects(group->subject_list);
	free_ip_ports(group->allowed_ips);
	
	return;
}

int fulllearn_pass3(struct gr_learn_file_node *subject, struct gr_learn_file_node *unused, FILE *stream)
{
	fseek(fulllearn_pass3in, 0, SEEK_SET);
	current_learn_subject = subject->filename;

	fflush(stdout);
	fulllearn_pass3parse();
	fflush(stdout);

	full_reduce_object_node(subject, NULL, NULL);
	full_reduce_ip_node(subject, NULL, NULL);
	full_reduce_id_node(subject, NULL, NULL);

	display_leaf(subject, NULL, stream);
	free_subject_full(subject);

	return 0;
}

void enforce_hidden_file(struct gr_learn_file_node *subject, char *filename)
{
	struct gr_learn_file_node *objects = subject->object_list;
	struct gr_learn_file_node *retobj;
	
	retobj = match_file_node(objects, filename);
	if (retobj->mode & GR_FIND && !strcmp(retobj->filename, filename))
		retobj->mode = 0;
	else if (retobj->mode & GR_FIND)
		insert_file(&(subject->object_list), filename, 0, 0);

	return;
}

int ensure_subject_security(struct gr_learn_file_node *subject,
			struct gr_learn_file_node *unused1,
			FILE *unused2)
{
	if (strcmp(subject->filename, "/"))
		return 0;

	enforce_hidden_file(subject, "/etc/ssh");
	enforce_hidden_file(subject, "/dev/mem");
	enforce_hidden_file(subject, "/dev/kmem");
	enforce_hidden_file(subject, "/dev/port");
	enforce_hidden_file(subject, "/proc/kcore");
	enforce_hidden_file(subject, GRSEC_DIR);
	enforce_hidden_file(subject, GRDEV_PATH);

	return 0;
}

int ensure_role_security(struct gr_learn_group_node *group,
			 struct gr_learn_user_node *user,
			FILE *unused)
{
	struct gr_learn_file_node *subjects;

	if (user)
		subjects = user->subject_list;
	else
		subjects = group->subject_list;

	traverse_file_tree(subjects, &ensure_subject_security, NULL, NULL);

	return 0;
}

void output_learn_header(FILE *stream)
{
	fprintf(stream, "role admin sA\n");
	fprintf(stream, "subject / rvka\n");
	fprintf(stream, "\t/ rwcdmlxi\n\n");
	fprintf(stream, "role default\n");
	fprintf(stream, "subject / {\n");
	fprintf(stream, "\t/\t\t\t\th\n");
	fprintf(stream, "\t-CAP_ALL\n");
	fprintf(stream, "\tconnect\tdisabled\n");
	fprintf(stream, "\tbind\tdisabled\n");
	fprintf(stream, "}\n\n");
	fflush(stream);

	return;
}

void output_role_info(struct gr_learn_group_node *group, struct gr_learn_user_node *user, FILE *stream)
{
	struct gr_learn_ip_node *allowed_ips = NULL;

	if (user) {
		fprintf(stream, "role %s u%s\n", user->rolename, strcmp(user->rolename, "root") ? "" : "G");
		if (!strcmp(user->rolename, "root")) {
			fprintf(stream, "role_transitions admin\n");
		}
		allowed_ips = user->allowed_ips;
	} else {
		fprintf(stream, "role %s g\n", group->rolename);
		allowed_ips = group->allowed_ips;
	}

	if (allowed_ips && !(grlearn_options & GR_DONT_LEARN_ALLOWED_IPS))
		traverse_ip_tree(allowed_ips, NULL, &display_only_ip, 0, stream);

	return;
}

void generate_full_learned_acls(FILE *learnlog, FILE *stream)
{
	struct gr_learn_group_node **group;
	struct gr_learn_user_node **user;

	output_learn_header(stream);

	fulllearn_pass1(learnlog);
	fseek(learnlog, 0, SEEK_SET);
	fulllearn_pass2(learnlog);
	
	fulllearn_pass3in = learnlog;
	group = role_list;

	if (!group)
		goto out;

	while (*group) {
		user = (*group)->users;
		if (!user) {
			current_learn_rolename = (*group)->rolename;
			current_learn_rolemode = GR_ROLE_GROUP;
			output_role_info((*group), NULL, stream);
			traverse_file_tree((*group)->subject_list, &fulllearn_pass3, NULL, stream);
		} else {	
			while (*user) {
				current_learn_rolename = (*user)->rolename;
				current_learn_rolemode = GR_ROLE_USER;
				output_role_info(NULL, (*user), stream);
				traverse_file_tree((*user)->subject_list, &fulllearn_pass3, NULL, stream);
				free_role_user_full(*user);
				user++;
			}
		}
		free_role_group_full(*group);
		group++;
	}
out:
	fprintf(stdout, "Full learning complete.\n");
	fclose(learnlog);
	return;
}
