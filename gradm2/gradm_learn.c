#include "gradm.h"

struct gr_learn_role_entry *default_role_entry;
struct gr_learn_role_entry **group_role_list;
struct gr_learn_role_entry **user_role_list;
struct gr_learn_role_entry **special_role_list;

extern FILE *learn_pass1in;
extern FILE *learn_pass2in;
extern int learn_pass1parse(void);
extern int learn_pass2parse(void);

void learn_pass1(FILE *stream)
{
	struct gr_learn_role_entry **tmp;
	struct gr_learn_file_tmp_node **tmptable;
	unsigned long i;
	u_int32_t table_size;

	learn_pass1in = stream;
	learn_pass1parse();

	if (default_role_entry && default_role_entry->hash) {
		if (default_role_entry->hash) {
			tmptable = (struct gr_learn_file_tmp_node **)default_role_entry->hash->table;
			table_size = default_role_entry->hash->table_size;
			sort_file_list(default_role_entry->hash);
			for (i = 0; i < table_size; i++) {
				if (tmptable[i] == NULL)
					continue;
				if (default_role_entry->rolemode & GR_ROLE_LEARN)
					insert_file(&(default_role_entry->subject_list), tmptable[i]->filename, tmptable[i]->mode, 1);
				else
					insert_file(&(default_role_entry->subject_list), tmptable[i]->filename, tmptable[i]->mode, 2);
			}
		}
		if (default_role_entry->rolemode & GR_ROLE_LEARN)
			reduce_ip_tree(default_role_entry->allowed_ips);
	}

	tmp = group_role_list;
	while (tmp && *tmp) {
		if ((*tmp)->hash) {
			tmptable = (struct gr_learn_file_tmp_node **)(*tmp)->hash->table;
			table_size = (*tmp)->hash->table_size;
			sort_file_list((*tmp)->hash);
			for (i = 0; i < table_size; i++) {
				if (tmptable[i] == NULL)
					continue;
				if ((*tmp)->rolemode & GR_ROLE_LEARN)
					insert_file(&((*tmp)->subject_list), tmptable[i]->filename, tmptable[i]->mode, 1);
				else
					insert_file(&((*tmp)->subject_list), tmptable[i]->filename, tmptable[i]->mode, 2);
			}
		}
		if ((*tmp)->rolemode & GR_ROLE_LEARN)
			reduce_ip_tree((*tmp)->allowed_ips);
		tmp++;
	}

	tmp = user_role_list;
	while (tmp && *tmp) {
		if ((*tmp)->hash) {
			tmptable = (struct gr_learn_file_tmp_node **)(*tmp)->hash->table;
			table_size = (*tmp)->hash->table_size;
			sort_file_list((*tmp)->hash);
			for (i = 0; i < table_size; i++) {
				if (tmptable[i] == NULL)
					continue;
				if ((*tmp)->rolemode & GR_ROLE_LEARN)
					insert_file(&((*tmp)->subject_list), tmptable[i]->filename, tmptable[i]->mode, 1);
				else
					insert_file(&((*tmp)->subject_list), tmptable[i]->filename, tmptable[i]->mode, 2);
			}
		}
		if ((*tmp)->rolemode & GR_ROLE_LEARN)
			reduce_ip_tree((*tmp)->allowed_ips);
		tmp++;
	}

	tmp = special_role_list;
	while (tmp && *tmp) {
		if ((*tmp)->hash) {
			tmptable = (struct gr_learn_file_tmp_node **)(*tmp)->hash->table;
			table_size = (*tmp)->hash->table_size;
			sort_file_list((*tmp)->hash);
			for (i = 0; i < table_size; i++) {
				if (tmptable[i] == NULL)
					continue;
				if ((*tmp)->rolemode & GR_ROLE_LEARN)
					insert_file(&((*tmp)->subject_list), tmptable[i]->filename, tmptable[i]->mode, 1);
				else
					insert_file(&((*tmp)->subject_list), tmptable[i]->filename, tmptable[i]->mode, 2);
			}
		}
		if ((*tmp)->rolemode & GR_ROLE_LEARN)
			reduce_ip_tree((*tmp)->allowed_ips);
		tmp++;
	}

	return;
}

void merge_acl_rules(void)
{
	struct gr_learn_role_entry *matchrole = NULL;
	struct gr_learn_file_node *matchsubj = NULL;
	struct role_acl *role;
	struct proc_acl *subject;
	struct file_acl *object;
	struct ip_acl *ipp;
	unsigned int i, x, y, port;

	for_each_role(role, current_role) {
		if (role->roletype & GR_ROLE_LEARN)
			continue;

		if (role->roletype & GR_ROLE_USER)
			matchrole = find_learn_role(user_role_list, role->rolename);
		else if (role->roletype & GR_ROLE_GROUP)
			matchrole = find_learn_role(group_role_list, role->rolename);
		else if (role->roletype & GR_ROLE_SPECIAL)
			matchrole = find_learn_role(special_role_list, role->rolename);
		else
			matchrole = default_role_entry;

		for_each_subject(subject, role) {
			if (!(subject->mode & GR_LEARN))
				continue;
			if (matchrole)
				matchsubj = match_file_node(matchrole->subject_list, subject->filename);
			if (matchrole && matchsubj) {
				if (matchsubj->subject == NULL) {
					matchsubj->subject = calloc(1, sizeof(struct gr_learn_subject_node));
					if (matchsubj->subject == NULL)
						failure("calloc");
				}

				matchsubj->subject->pax_flags = subject->pax_flags;

				matchsubj->subject->cap_raise = cap_combine(matchsubj->subject->cap_raise,
									    cap_invert(subject->cap_drop));
				matchsubj->subject->resmask |= subject->resmask;

				matchsubj->subject->inaddr_any_override = subject->inaddr_any_override;

				for (i = 0; i < subject->user_trans_num; i++) {
					x = *(subject->user_transitions + i);
					insert_learn_id_transition(&(matchsubj->user_trans_list), x, x, x);
				}
				for (i = 0; i < subject->group_trans_num; i++) {
					x = *(subject->group_transitions + i);
					insert_learn_id_transition(&(matchsubj->group_trans_list), x, x, x);
				}
				for (i = 0; i < GR_NLIMITS; i++) {
					if (subject->res[i].rlim_cur > matchsubj->subject->res[i].rlim_cur)
						matchsubj->subject->res[i].rlim_cur = subject->res[i].rlim_cur;
					if (subject->res[i].rlim_max > matchsubj->subject->res[i].rlim_max)
						matchsubj->subject->res[i].rlim_max = subject->res[i].rlim_max;
				}
				for_each_object(object, subject) {
					insert_learn_object(matchsubj, conv_filename_to_struct(object->filename, object->mode));
				}
				for (i = 0; i < subject->ip_num; i++) {
					ipp = subject->ips[i];
					if (ipp->mode == GR_IP_CONNECT) {
						for (port = ipp->low; port <= ipp->high; port++)
						for (x = 0; x < 5; x++)
						for (y = 0; y < 256; y++)
						if ((ipp->type & (1 << x)) && (ipp->proto[y / 32] & (1 << y % 32)))
							insert_ip(&(matchsubj->connect_list), ipp->addr, port, x, y);
					} else if (ipp->mode == GR_IP_BIND) {
						for (port = ipp->low; port <= ipp->high; port++)
						for (x = 0; x < 5; x++)
						for (y = 0; y < 256; y++)
						if ((ipp->type & (1 << x)) && (ipp->proto[y / 32] & (1 << y % 32)))
							insert_ip(&(matchsubj->bind_list), ipp->addr, port, x, y);
					}
				}
			}
		}
	}
			

	return;
}

void learn_pass2(FILE *stream)
{
	struct gr_learn_role_entry **tmp;
	struct gr_learn_file_node *subjects;
	
	learn_pass2in = stream;
	learn_pass2parse();

	merge_acl_rules();

	if (default_role_entry) {
		subjects = default_role_entry->subject_list;
		traverse_file_tree(subjects, &full_reduce_object_node, NULL, NULL);
		traverse_file_tree(subjects, &full_reduce_ip_node, NULL, NULL);
		traverse_file_tree(subjects, &ensure_subject_security, NULL, NULL);
	}

	tmp = group_role_list;
	while (tmp && *tmp) {
		subjects = (*tmp)->subject_list;
		traverse_file_tree(subjects, &full_reduce_object_node, NULL, NULL);
		traverse_file_tree(subjects, &full_reduce_ip_node, NULL, NULL);
		traverse_file_tree(subjects, &ensure_subject_security, NULL, NULL);
		tmp++;
	}

	tmp = user_role_list;
	while (tmp && *tmp) {
		subjects = (*tmp)->subject_list;
		traverse_file_tree(subjects, &full_reduce_object_node, NULL, NULL);
		traverse_file_tree(subjects, &full_reduce_ip_node, NULL, NULL);
		traverse_file_tree(subjects, &ensure_subject_security, NULL, NULL);
		tmp++;
	}

	tmp = special_role_list;
	while (tmp && *tmp) {
		subjects = (*tmp)->subject_list;
		traverse_file_tree(subjects, &full_reduce_object_node, NULL, NULL);
		traverse_file_tree(subjects, &full_reduce_ip_node, NULL, NULL);
		traverse_file_tree(subjects, &ensure_subject_security, NULL, NULL);
		tmp++;
	}

	return;
}

void
perform_parse_and_reduce(FILE *learnlog)
{
	learn_pass1(learnlog);
	fseek(learnlog, 0, SEEK_SET);
	learn_pass2(learnlog);

	fclose(learnlog);

	return;
}

void display_learn_logs(FILE *stream)
{
	struct gr_learn_role_entry **tmp;
	struct gr_learn_file_node *subjects;
	struct gr_learn_ip_node *allowed_ips;
	char rolemode[17];
	
	if (default_role_entry) {
		if (!(default_role_entry->rolemode & GR_ROLE_LEARN))
			fprintf(stream, "###  THE BELOW SUBJECT(S) SHOULD BE ADDED TO THE DEFAULT ROLE ###\n");
		else
			fprintf(stream, "role default G\n");
		subjects = default_role_entry->subject_list;
		allowed_ips = default_role_entry->allowed_ips;
		if (allowed_ips)
			traverse_ip_tree(allowed_ips, NULL, &display_only_ip, 0, stream);
		if (subjects)
			display_tree(subjects, stream);

		fprintf(stream, "\n");
	}

	tmp = group_role_list;
	while (tmp && *tmp) {
		if (!((*tmp)->rolemode & GR_ROLE_LEARN))
			fprintf(stream, "###  THE BELOW SUBJECT(S) SHOULD BE ADDED TO THE GROUP ROLE \"%s\" ###\n", (*tmp)->rolename);
		else {
			conv_role_mode_to_str((*tmp)->rolemode, rolemode, sizeof(rolemode));
			fprintf(stream, "role %s %s\n", (*tmp)->rolename, rolemode);
		}
		subjects = (*tmp)->subject_list;
		allowed_ips = (*tmp)->allowed_ips;
		if (allowed_ips)
			traverse_ip_tree(allowed_ips, NULL, &display_only_ip, 0, stream);
		if (subjects)
			display_tree(subjects, stream);

		fprintf(stream, "\n");
		tmp++;
	}

	tmp = user_role_list;
	while (tmp && *tmp) {
		if (!((*tmp)->rolemode & GR_ROLE_LEARN))
			fprintf(stream, "###  THE BELOW SUBJECT(S) SHOULD BE ADDED TO THE USER ROLE \"%s\" ###\n", (*tmp)->rolename);
		else {
			conv_role_mode_to_str((*tmp)->rolemode, rolemode, sizeof(rolemode));
			fprintf(stream, "role %s %s\n", (*tmp)->rolename, rolemode);
		}
		subjects = (*tmp)->subject_list;
		allowed_ips = (*tmp)->allowed_ips;
		if (allowed_ips)
			traverse_ip_tree(allowed_ips, NULL, &display_only_ip, 0, stream);
		if (subjects)
			display_tree(subjects, stream);

		fprintf(stream, "\n");
		tmp++;
	}

	tmp = special_role_list;
	while (tmp && *tmp) {
		if (!((*tmp)->rolemode & GR_ROLE_LEARN))
			fprintf(stream, "###  THE BELOW SUBJECT(S) SHOULD BE ADDED TO THE SPECIAL ROLE \"%s\" ###\n", (*tmp)->rolename);
		else {
			conv_role_mode_to_str((*tmp)->rolemode, rolemode, sizeof(rolemode));
			fprintf(stream, "role %s %s\n", (*tmp)->rolename, rolemode);
		}
		subjects = (*tmp)->subject_list;
		allowed_ips = (*tmp)->allowed_ips;
		if (allowed_ips)
			traverse_ip_tree(allowed_ips, NULL, &display_only_ip, 0, stream);
		if (subjects)
			display_tree(subjects, stream);

		fprintf(stream, "\n");
		tmp++;
	}

	return;
}	


void
handle_learn_logs(FILE *learnlog, FILE * stream)
{
	parse_acls();
	expand_acls();
	perform_parse_and_reduce(learnlog);
	display_learn_logs(stream);

	return;
}
