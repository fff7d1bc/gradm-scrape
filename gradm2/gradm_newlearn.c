#include "gradm.h"

struct gr_learn_file_node *cachednode = NULL;
unsigned int cachedlen = 0;

void add_grlearn_option(u_int32_t option)
{
	grlearn_options |= option;

	return;
}

int is_protected_path(char *filename, u_int32_t mode)
{
	char **tmp;
	unsigned int len;

	if (!(mode & (GR_WRITE | GR_APPEND)))
		return 0;

	tmp = protected_paths;
	if (tmp == NULL)
		return 0;

	while (*tmp) {
		len = strlen(*tmp);
		if (!strncmp(filename, *tmp, len) &&
		    (filename[len] == '\0' || filename[len] == '/'))
			return 1;
		tmp++;
	}

	return 0;
}

void enforce_high_protected_paths(struct gr_learn_file_node *subject)
{
	struct gr_learn_file_tmp_node **tmptable;
	char **tmp;
	unsigned int len;
	unsigned long i;

	tmp = high_protected_paths;
	if (tmp == NULL)
		return;

	tmptable = (struct gr_learn_file_tmp_node **)subject->hash->table;

	while (*tmp) {
		len = strlen(*tmp);
		for (i = 0; i < subject->hash->table_size; i++) {
			if (tmptable[i] == NULL)
				continue;
			if (!tmptable[i]->mode)
				continue;
			if (!strncmp(tmptable[i]->filename, *tmp, len) &&
			    (tmptable[i]->filename[len] == '\0' || tmptable[i]->filename[len] == '/'))
				goto next;
		}
		cachednode = NULL;
		cachedlen = 0;
		insert_file(&(subject->object_list), *tmp, 0, 0);
next:
		tmp++;
	}
	return;
}

void match_role(struct gr_learn_group_node *grouplist, uid_t uid, gid_t gid, struct gr_learn_group_node **group,
		struct gr_learn_user_node **user)
{
	struct gr_learn_group_node *tmpgroup;
	struct gr_learn_user_node *tmpuser;

	*group = NULL;
	*user = NULL;

	for_each_list_entry(tmpgroup, grouplist) {
		for_each_list_entry(tmpuser, tmpgroup->users) {
			if (tmpuser->uid == uid) {
				*user = tmpuser;
				return;
			}
		}
	}


	for_each_list_entry(tmpgroup, grouplist) {
		if (tmpgroup->gid == gid) {
			*group = tmpgroup;
			return;
		}
	}
				
	return;
}

void traverse_roles(struct gr_learn_group_node *grouplist, 
		    int (*act)(struct gr_learn_group_node *group, struct gr_learn_user_node *user, FILE *stream),
		    FILE *stream)
{
	struct gr_learn_group_node *tmpgroup;
	struct gr_learn_user_node *tmpuser;

	for_each_list_entry(tmpgroup, grouplist) {
		if (tmpgroup->users == NULL)
			act(tmpgroup, NULL, stream);
		else {
			for_each_list_entry(tmpuser, tmpgroup->users) {
				act(tmpgroup, tmpuser, stream);
			}
		}
	}

	return;
}

/* uses mergesort, preserves prev and next functionality,
   filelist may be modified by the sort
   modified from algorithm by Simon Tatham
*/
void sort_file_node_list(struct gr_learn_file_node *root)
{
	struct gr_learn_file_node **filelist;
	int count = 0;
	int i;
	int list_size = 1;
	int num_merges;
	int left_size, right_size;
	struct gr_learn_file_node *cur, *left, *right, *end;
	char *basename;
	unsigned int baselen;

	if (root == NULL)
		return;

	filelist = &root->leaves;

	if (*filelist == NULL)
		return;

	basename = root->filename;
	baselen = strlen(basename);
	/* special case the root / */
	if (baselen == 1)
		baselen = 0;

	for_each_list_entry(cur, *filelist) {
		sort_file_node_list(cur);
		count++;
	}

	if (count < 2)
		return;

	while (1) {
		left = *filelist;
		*filelist = NULL;
		end = NULL;

		num_merges = 0;

		while (left) {
			num_merges++;
			right = left;
			left_size = 0;

			for (i = 0; i < list_size; i++) {
				left_size++;
				right = right->next;
				if (right == NULL)
					break;
			}

			right_size = list_size;

			while (left_size > 0 || (right_size > 0 && right != NULL)) {
				if (left_size == 0) {
					cur = right;
					right = right->next;
					right_size--;
				} else if (right_size == 0 || right == NULL ||
					   strcmp(left->filename + baselen + 1, right->filename + baselen + 1) <= 0) {
					cur = left;
					left = left->next;
					left_size--;
				} else {
					cur = right;
					right = right->next;
					right_size--;
				}

				if (end)
					end->next = cur;
				else
					*filelist = cur;
				cur->prev = end;
				end = cur;
			}

			left = right;
		}

		end->next = NULL;

		if (num_merges <= 1)
			return;

		list_size <<= 1;
	}

	return;
}

int display_role(struct gr_learn_group_node *group, struct gr_learn_user_node *user, FILE *stream)
{
	struct gr_learn_file_node *subject = NULL;

	output_role_info(group, user, stream);

	if (user) {
		if (user->subject_list)
			sort_file_node_list(user->subject_list);
		subject = user->subject_list;
	} else {
		if (group->subject_list)
			sort_file_node_list(group->subject_list);
		subject = group->subject_list;
	}

	if (subject)
		display_tree(subject, stream);

	fprintf(stream, "\n");

	return 0;
}

void display_roles(struct gr_learn_group_node *grouplist, FILE *stream)
{
	output_learn_header(stream);
	traverse_roles(grouplist, &display_role, stream);
	return;
}
	
struct gr_learn_group_node *find_insert_group(struct gr_learn_group_node *grouplist, gid_t gid)
{
	struct gr_learn_group_node *tmp;

	for_each_list_entry(tmp, grouplist) {
		if (tmp->gid == gid)
			return tmp;
	}

	return NULL;
}

unsigned long count_users(struct gr_learn_group_node *group)
{
	struct gr_learn_user_node *tmp;
	unsigned long ret = 0;

	for_each_list_entry(tmp, group->users)
		ret++;

	return ret;
}

static unsigned long count_users_nomultgroups(struct gr_learn_group_node *group)
{
	struct gr_learn_user_node *tmp;
	unsigned long ret = 0;

	for_each_list_entry(tmp, group->users) {
		if (!tmp->multgroups)
			ret++;
	}

	return ret;
}

struct gr_learn_user_node * create_new_user(char *username, uid_t uid, struct gr_learn_group_node *group, int multgroups)
{
	struct gr_learn_user_node *user;

	user = (struct gr_learn_user_node *)gr_stat_alloc(sizeof(struct gr_learn_user_node));
	user->rolename = gr_strdup(username);
	user->uid = uid;
	user->group = group;
	user->multgroups = multgroups;

	return user;
}

struct gr_learn_group_node * create_new_group(char *groupname, gid_t gid)
{
	struct gr_learn_group_node *group;

	group = (struct gr_learn_group_node *)gr_stat_alloc(sizeof(struct gr_learn_group_node));
	group->rolename = gr_strdup(groupname);
	group->gid = gid;

	return group;
}

void insert_user(struct gr_learn_group_node **grouplist, char *username, char *groupname, uid_t uid, gid_t gid)
{
	struct gr_learn_group_node *group;
	struct gr_learn_group_node *tmpgroup;
	struct gr_learn_user_node *user;
	struct gr_learn_user_node *tmpuser;
	int multgroups = 0;

	/* first check to see if the user exists in any group */

	for_each_list_entry(group, *grouplist) {
		for_each_list_entry(user, group->users) {
			/* found them, check if we've noted the group membership observed */
			if (user->uid == uid) {
				/* user belongs to multiple groups, don't use them for reduction */
				if (user->group->gid != gid) {
					user->multgroups = 1;
					multgroups = 1;
				} else /* this entry is a duplicate */
					return;
			}
		}
	}

	group = find_insert_group(*grouplist, gid);

	if (group == NULL) {
		group = create_new_group(groupname, gid);
		establish_new_head(*grouplist, group, tmpgroup);
	}

	user = create_new_user(username, uid, group, multgroups);
	establish_new_head(group->users, user, tmpuser);

	return;
}

void free_entire_user_node_list(struct gr_learn_user_node **userlist)
{
	struct gr_learn_user_node *freeuser, *tmpuser;

	for_each_list_entry(tmpuser, *userlist) {
		freeuser = tmpuser;
		tmpuser = tmpuser->next;
		free(freeuser->rolename);
		gr_stat_free(freeuser);
	}
		
	*userlist = NULL;

	return;
}

void unlink_and_free_user_node_entry(struct gr_learn_user_node *remove)
{
	if (remove->prev == NULL) {
		remove->group->users = remove->next;
		if (remove->next != NULL)
			remove->next->prev = NULL;
	} else {
		remove->prev->next = remove->next;
		if (remove->next != NULL)
			remove->next->prev = remove->prev;
	}
	free(remove->rolename);
	gr_stat_free(remove);
		
	return;
}

struct gr_learn_file_node * unlink_and_free_file_node_entry(struct gr_learn_file_node *remove, struct gr_learn_file_node **filelist)
{
	struct gr_learn_file_node *ret;

	ret = remove->next;

	if (remove->prev == NULL) {
		*filelist = remove->next;
		if (remove->next != NULL)
			remove->next->prev = NULL;
	} else {
		remove->prev->next = remove->next;
		if (remove->next != NULL)
			remove->next->prev = remove->prev;
	}
	free(remove->filename);
	gr_stat_free(remove);
	
	/* clear cache when removing a node */
	cachednode = NULL;
	cachedlen = 0;

	return ret;
}

/* unlink a file node entry, return the next entry, and stuff the unlinked entry in the argument */
struct gr_learn_file_node * unlink_file_node_entry(struct gr_learn_file_node *remove, struct gr_learn_file_node **filelist, struct gr_learn_file_node ** unlinked)
{
	struct gr_learn_file_node *ret;

	ret = remove->next;

	if (remove->prev == NULL) {
		*filelist = remove->next;
		if (remove->next != NULL)
			remove->next->prev = NULL;
	} else {
		remove->prev->next = remove->next;
		if (remove->next != NULL)
			remove->next->prev = remove->prev;
	}
	
	/* clear cache when removing a node */
	cachednode = NULL;
	cachedlen = 0;

	*unlinked = remove;

	return ret;
}

struct gr_learn_ip_node * unlink_and_free_ip_node_entry(struct gr_learn_ip_node *remove, struct gr_learn_ip_node **iplist)
{
	struct gr_learn_ip_node *ret;

	ret = remove->next;

	if (remove->prev == NULL) {
		*iplist = remove->next;
		if (remove->next != NULL)
			remove->next->prev = NULL;
	} else {
		remove->prev->next = remove->next;
		if (remove->next != NULL)
			remove->next->prev = remove->prev;
	}
	gr_stat_free(remove);
	
	return ret;
}

struct gr_learn_group_node * unlink_and_free_group_node_entry(struct gr_learn_group_node *remove, struct gr_learn_group_node **grouplist)
{
	struct gr_learn_group_node *ret;

	ret = remove->next;

	if (remove->prev == NULL) {
		*grouplist = remove->next;
		if (remove->next != NULL)
			remove->next->prev = NULL;
	} else {
		remove->prev->next = remove->next;
		if (remove->next != NULL)
			remove->next->prev = remove->prev;
	}
	free(remove->rolename);
	gr_stat_free(remove);
		
	return ret;
}

void reduce_roles(struct gr_learn_group_node **grouplist)
{
	unsigned int thresh = 3;
	struct gr_learn_group_node *group, *group2;
	struct gr_learn_user_node *tmpuser, *tmpuser2;
	unsigned long num;
	int removed = 0;

	for_each_list_entry(group, *grouplist) {
		num = count_users_nomultgroups(group);
		if (num < thresh)
			continue;
		free_entire_user_node_list(&group->users);
	}
	
	/* make sure only one role is created for each user */
	for_each_list_entry(group, *grouplist) {
		for_each_list_entry(tmpuser, group->users) {
			if (!tmpuser->multgroups)
				continue;
			/* check to see if the user is in another group,
			   and remove them from this group if so */
			for_each_removable_list_entry(group2, group->next) {
				for_each_list_entry(tmpuser2, group2->users) {
					if (tmpuser2->uid == tmpuser->uid) {
						unlink_and_free_user_node_entry(tmpuser2);
						/* we removed the only user in this group, so remove
						   the group as well
						*/
						if (group2->users == NULL) {
							group2 = unlink_and_free_group_node_entry(group2, grouplist);
							removed = 1;
						}
						goto done;
					}
				}
done:
				for_each_removable_list_entry_end(group2);
			}
		}
	}

	return;
}

void traverse_file_tree(struct gr_learn_file_node *base,
		   int (*act)(struct gr_learn_file_node *node, struct gr_learn_file_node *optarg, FILE *stream),
		   struct gr_learn_file_node *optarg, FILE *stream)
{
	struct gr_learn_file_node *node;

	if (!base)
		return;

	act(base, optarg, stream);

	for_each_list_entry(node, base->leaves)
		traverse_file_tree(node, act, optarg, stream);

	return;
}

struct gr_learn_file_node *match_file_node(struct gr_learn_file_node *base,
					const char *filename)
{
	struct gr_learn_file_node *node, *ret;
	unsigned int baselen, filelen;

	filelen = strlen(filename);

	if (base == NULL)
		return base;

	baselen = strlen(base->filename);
	if ((filelen == baselen) && !strcmp(base->filename, filename))
		return base;

	if ((baselen >= filelen) || (filename[baselen] != '/' && baselen != 1) ||
	    strncmp(base->filename, filename, baselen))
		return NULL;

	for_each_list_entry(node, base->leaves) {
		if ((ret = match_file_node(node, filename)))
			return ret;
	}
	
	return base;
}

unsigned long count_nodes(struct gr_learn_file_node *node)
{
	unsigned long ret = 0;

	for_each_list_entry(node, node)
		ret++;

	return ret;
}

unsigned long count_leaf_nodes(struct gr_learn_file_node *node)
{
	unsigned long ret = 0;

	for_each_list_entry(node, node) {
		if (node->leaves == NULL)
			ret++;
	}

	return ret;
}

unsigned long count_total_leaves(struct gr_learn_file_node *node)
{
	unsigned long leaves = 0;
	struct gr_learn_file_node *tmp;

	for_each_list_entry(tmp, node->leaves) {
		leaves++;
		leaves += count_total_leaves(tmp);
	}

	return leaves;
}

unsigned long count_max_depth(struct gr_learn_file_node *node)
{
	unsigned long max = 0, tmpmax = 0;
	struct gr_learn_file_node *tmp;

	if (node->leaves == NULL)
		return 0;

	max++;
	for_each_list_entry(tmp, node->leaves) {
		tmpmax = count_max_depth(tmp);
		if ((max + tmpmax) > max)
			max = tmpmax + max;
	}

	return max;
}	

unsigned long count_nested_depth(struct gr_learn_file_node *node)
{
	unsigned long depth = 0;
	struct gr_learn_file_node *tmp;

	for_each_parent_entry(tmp, node->parent)
		depth++;

	return depth;
}	

/* this reduces all files in a directory, but not including any subdirectories */
int reduce_all_children(struct gr_learn_file_node *node)
{
	unsigned long not_leaf = 0;
	unsigned long i;
	struct gr_learn_file_node *tmp;
	int removed = 0;

	for_each_list_entry(tmp, node->leaves) {
		if (tmp->leaves != NULL) {
			not_leaf++;
			continue;
		}
		node->mode |= tmp->mode;
		if (node->subject == NULL || tmp->subject == NULL)
			continue;
		/* merge capabilities */
		node->subject->cap_raise = cap_combine(node->subject->cap_raise, tmp->subject->cap_raise);
		/* merge resources */
		node->subject->resmask |= tmp->subject->resmask;
		for (i = 0; i < GR_NLIMITS; i++) {
			if (tmp->subject->res[i].rlim_cur > node->subject->res[i].rlim_cur)
				node->subject->res[i].rlim_cur = tmp->subject->res[i].rlim_cur;
			if (tmp->subject->res[i].rlim_max > node->subject->res[i].rlim_max)
				node->subject->res[i].rlim_max = tmp->subject->res[i].rlim_max;
		}
		/* merge socket families */
		for (i = 0; i < SIZE(node->subject->sock_families); i++)
			node->subject->sock_families[i] |= tmp->subject->sock_families[i];
	}

	for_each_removable_list_entry(tmp, node->leaves) {
		if (tmp->leaves != NULL)
			goto next_entry;
		tmp = unlink_and_free_file_node_entry(tmp, &node->leaves);
		removed = 1;
next_entry:
		for_each_removable_list_entry_end(tmp);
	}

	if (!not_leaf)
		node->leaves = NULL;

	return 0;
}

int reduce_all_leaves(struct gr_learn_file_node *node)
{
	struct gr_learn_file_node *tmp;
	unsigned int i;
	int removed = 0;

	for_each_removable_list_entry(tmp, node->leaves) {
		reduce_all_leaves(tmp);
		node->mode |= tmp->mode;
		if (node->subject == NULL || tmp->subject == NULL)
			goto remove_node;
		/* merge capabilities */
		node->subject->cap_raise = cap_combine(node->subject->cap_raise,
						       tmp->subject->cap_raise);
		/* merge resources */
		node->subject->resmask |= tmp->subject->resmask;
		for (i = 0; i < GR_NLIMITS; i++) {
			if (tmp->subject->res[i].rlim_cur > node->subject->res[i].rlim_cur)
				node->subject->res[i].rlim_cur = tmp->subject->res[i].rlim_cur;
			if (tmp->subject->res[i].rlim_max > node->subject->res[i].rlim_max)
				node->subject->res[i].rlim_max = tmp->subject->res[i].rlim_max;
		}
		/* merge socket families */
		for (i = 0; i < SIZE(node->subject->sock_families); i++)
			node->subject->sock_families[i] |= tmp->subject->sock_families[i];
remove_node:
		tmp = unlink_and_free_file_node_entry(tmp, &node->leaves);
		removed = 1;
		for_each_removable_list_entry_end(tmp);
	}

	node->leaves = NULL;

	return 0;
}

void greatest_occurring_modes(struct gr_learn_file_node *node, u_int32_t *modeary)
{
	struct gr_learn_file_node *tmp;
	u_int32_t modes[12] = { GR_FIND,
			    GR_FIND | GR_READ,
			    GR_FIND | GR_READ | GR_WRITE,
			    GR_FIND | GR_READ | GR_EXEC,
			    GR_FIND | GR_EXEC,
			    GR_FIND | GR_WRITE,
			    GR_FIND | GR_WRITE | GR_CREATE,
			    GR_FIND | GR_WRITE | GR_DELETE,
			    GR_FIND | GR_WRITE | GR_CREATE | GR_DELETE,
			    GR_FIND | GR_READ | GR_WRITE | GR_CREATE | GR_DELETE,
			    GR_FIND | GR_READ | GR_WRITE | GR_DELETE,
			    GR_FIND | GR_READ | GR_WRITE | GR_CREATE,
			};
	unsigned long counts[12] = {0};
	u_int16_t max, max2;
	int i;

	for_each_list_entry(tmp, node->leaves) {
		for (i = 0; i < 12; i++) {
			if (tmp->mode == modes[i])
				counts[i]++;
		}
	}

	max = 0;
	max2 = 0;

	for (i = 0; i < 12; i++) {
		if (counts[i] > counts[max])
			max = i;
		else if (max == max2 || counts[i] > counts[max2])
			max2 = i;
	}

	
	*modeary = modes[max];
	*(modeary + 1) = modes[max2];
}

int reduce_children_mode(struct gr_learn_file_node *node)
{
	struct gr_learn_file_node *tmp;
	u_int32_t modes[2];
	int ret = 0;
	int tmpdir = 0;
	int removed = 0;

	if (node->leaves == NULL)
		return 0;
	
	greatest_occurring_modes(node, (u_int32_t *)&modes);

	node->mode |= modes[0];
	node->mode |= modes[1];

	if (node->mode == (GR_FIND | GR_READ | GR_WRITE | GR_CREATE | GR_DELETE))
		tmpdir = 1;

	for_each_removable_list_entry(tmp, node->leaves) {
		if (((tmpdir && !(tmp->mode & GR_EXEC)) ||
		     (tmp->mode == modes[0] || tmp->mode == modes[1]))
		    && tmp->leaves == NULL) {
			ret++;
			tmp = unlink_and_free_file_node_entry(tmp, &node->leaves);
			removed = 1;
		}
		for_each_removable_list_entry_end(tmp);
	}

	return ret;
}

int analyze_node_read_permissions(struct gr_learn_file_node *node)
{
	struct gr_learn_file_node *tmp;

	for_each_list_entry(tmp, node->leaves) {
		if ((tmp->mode & GR_WRITE) && !(tmp->mode & GR_READ))
			return 0;
		if (!analyze_node_read_permissions(tmp))
			return 0;
	}

	return 1;
}

int analyze_node_write_permissions(struct gr_learn_file_node *node)
{
	struct gr_learn_file_node *tmp;

	for_each_list_entry(tmp, node->leaves) {
		if (!(tmp->mode & GR_WRITE) && (tmp->mode & GR_READ))
			return 0;
		if (!analyze_node_write_permissions(tmp))
			return 0;
	}

	return 1;
}

int analyze_child_read_permissions(struct gr_learn_file_node *node)
{
	struct gr_learn_file_node *tmp;

	for_each_list_entry(tmp, node->leaves) {
		if (tmp->leaves)
			continue;
		if ((tmp->mode & GR_WRITE) && !(tmp->mode & GR_READ))
			return 0;
	}

	return 1;
}

int analyze_child_write_permissions(struct gr_learn_file_node *node)
{
	struct gr_learn_file_node *tmp;

	for_each_list_entry(tmp, node->leaves) {
		if (tmp->leaves)
			continue;
		if (!(tmp->mode & GR_WRITE) && (tmp->mode & GR_READ))
			return 0;
	}

	return 1;
}

int *analyze_node_reduction(struct gr_learn_file_node *node)
{
	int reduce_child_thresh = 4;
	int reduce_leaves_thresh = 8;
	int reduction_level = 0;
	unsigned long node_num;
	unsigned long child_num;
	unsigned long depth_num;
	unsigned long nested_num;
	int child_reduced = 0;
	char **tmp;

	/* revert all the changes i made to this function */
	if (node->leaves == NULL)
		return NULL;

	tmp = dont_reduce_dirs;
	if (tmp) {
		while (*tmp) {
			if (!strcmp(node->filename, *tmp))
				return NULL;
			tmp++;
		}
	}

	tmp = always_reduce_dirs;
	if (tmp) {
		while (*tmp) {
			if (!strcmp(node->filename, *tmp))
				return (int *)&reduce_all_leaves;
			tmp++;
		}
	}

	node_num = count_leaf_nodes(node->leaves);
	child_num = count_total_leaves(node);
	depth_num = count_max_depth(node);
	nested_num = count_nested_depth(node);

	if (node_num > 3)
		reduction_level++;
	if (node_num > 6)
		reduction_level++;
	if (node_num > 10)
		reduction_level++;
	if (node_num > 15)
		reduction_level++;
	if (node_num > 20)
		reduction_level++;
	if (nested_num > 2)
		reduction_level++;
	if (nested_num > 4)
		reduction_level++;
	if (nested_num > 6)
		reduction_level++;
	if (child_num > 5)
		reduction_level++;
	if (child_num > 10)
		reduction_level++;
	if (child_num > 20)
		reduction_level++;
	if (child_num > 40)
		reduction_level++;
	if (child_num > 80)
		reduction_level++;
	if (depth_num > 2)
		reduction_level++;
	if (depth_num > 4)
		reduction_level++;
	if (depth_num > 6)
		reduction_level++;

	tmp = high_reduce_dirs;
	if (tmp) {
		while (*tmp) {
			if (!strcmp(node->filename, *tmp) && ((node_num > 2) || child_num > 5))
				reduction_level *= 2;
			tmp++;
		}
	}

	if (node->subject)
		goto final;

	if (analyze_node_read_permissions(node) || analyze_node_write_permissions(node))
		reduction_level *= 2;
	else {
		if (reduction_level >= reduce_child_thresh) {
			child_reduced = reduce_children_mode(node);
			if (child_reduced > ((3 *node_num) / 4))
				return 0;
		}
	}

final:
	if (reduction_level >= reduce_leaves_thresh)
		return (int *)&reduce_all_leaves;
	else if (reduction_level >= reduce_child_thresh)
		return (int *)&reduce_all_children;
	else
		return NULL;
}

/* for this stage based on some heuristics we decide if for a given directory,
   all files within it should be reduced, or if all files and subdirectories in
   it should be reduced
*/
int second_reduce_node(struct gr_learn_file_node *node,
		       struct gr_learn_file_node *unused1, FILE *unused)
{
	int (* retval)(struct gr_learn_file_node *node);

	retval = (int (*)(struct gr_learn_file_node *))analyze_node_reduction(node);

	if (retval)
		retval(node);

	return 0;
}		

void second_stage_reduce_tree(struct gr_learn_file_node *base)
{
	return traverse_file_tree(base, &second_reduce_node, NULL, NULL);
}

int third_reduce_node(struct gr_learn_file_node *node,
		       struct gr_learn_file_node *unused1, FILE *unused)
{
	struct gr_learn_file_node *tmp;
	int removed = 0;

	for_each_removable_list_entry(tmp, node->leaves) {
		if (tmp->leaves)
			goto next_entry;
		if (tmp->mode == node->mode ||
		    (((node->mode & (GR_WRITE | GR_CREATE)) == (GR_WRITE | GR_CREATE)) &&
		    (tmp->mode & GR_WRITE))) {
			node->mode |= tmp->mode;
			tmp = unlink_and_free_file_node_entry(tmp, &node->leaves);
			removed = 1;
		}
next_entry:
		for_each_removable_list_entry_end(tmp);
	}

	return 0;
}	
		

void third_stage_reduce_tree(struct gr_learn_file_node *base)
{
	return traverse_file_tree(base, &third_reduce_node, NULL, NULL);
}

struct gr_learn_file_node *do_find_insert_file(struct gr_learn_file_node **base,
					char *filename, unsigned int filelen)
{
	struct gr_learn_file_node *node, *tmpnode, *ret;
	unsigned int baselen;

	/* base needs to at least contain a root node for /, if it doesn't then we add it here */
	if (!*base) {
		*base = (struct gr_learn_file_node *)gr_stat_alloc(sizeof(struct gr_learn_file_node));
		/* the base has a NULL parent */
		(*base)->parent = NULL;
		return *base;
	}

	baselen = strlen((*base)->filename);
	/* simple lookup, the basename we gave was a match for the filename we were trying to add */
	if ((filelen == baselen) && !strcmp((*base)->filename, filename))
		return *base;

	node = (*base)->leaves;

	/* if there are no leaves for this base and the directory for the base matches
	   the file we're inserting, add the first leaf
	*/
	if (!node && (baselen < filelen) && (baselen == 1 || filename[baselen] == '/') &&
	    !strncmp((*base)->filename, filename, baselen)) {
		(*base)->leaves = node = (struct gr_learn_file_node *)gr_stat_alloc(sizeof(struct gr_learn_file_node));
		node->parent = *base;
		cachednode = *base;
		cachedlen = baselen;
		return node;
	} else if (!node) {
		/* there are no leaves for this base, and it didn't match the filename we're inserting */
		return NULL;
	}

	for_each_list_entry(tmpnode, node) {
		ret = do_find_insert_file(&tmpnode, filename, filelen);
		if (ret)
			return ret;
	}
	
	/* this is not a match for the file we're inserting */
	if ((baselen >= filelen) || (baselen != 1 && filename[baselen] != '/') ||
	    strncmp((*base)->filename, filename, baselen))
		return NULL;

	cachednode = *base;
	cachedlen = baselen;
	ret = (struct gr_learn_file_node *)gr_stat_alloc(sizeof(struct gr_learn_file_node));
	ret->parent = *base;

	establish_new_head((*base)->leaves, ret, tmpnode);

	return ret;
}

#ifdef GRADM_DEBUG
static struct gr_learn_file_node *find_file(struct gr_learn_file_node *filelist, char *filename)
{
	struct gr_learn_file_node *tmp, *ret;
	unsigned int alen, blen;

	if (filelist == NULL)
		return NULL;

	alen = strlen(filelist->filename);
	blen = strlen(filename);

	/* return if we've found a perfect match */
	if (alen == blen && !strcmp(filelist->filename, filename))
		return filelist;

	if (alen >= blen)
		return NULL;

	/* if this is a subdirectory match, then work our way up through the leaves to find
	   the most specific match to return
	*/
	if (!strncmp(filelist->filename, filename, alen) && (alen == 1 || filename[alen] == '/')) {
		for_each_list_entry(tmp, filelist->leaves) {
			ret = find_file(tmp, filename);
			if (ret != NULL)
				return ret;
		}
		return filelist;
	}

	/* if this wasn't a subdirectory match, then try to match against the other nodes at the
	   current level
	*/
	for_each_list_entry(tmp, filelist->leaves) {
		ret = find_file(tmp, filename);
		if (ret)
			return ret;
	}

	return NULL;
}
#endif

struct gr_learn_file_node *find_insert_file(struct gr_learn_file_node **base,
					char *filename, unsigned int filelen)
{
	if (cachednode && (cachedlen < filelen) && !strncmp(cachednode->filename, filename, cachedlen)
	    && filename[cachedlen] == '/') {
		return do_find_insert_file(&cachednode, filename, filelen);
	} else if (cachednode && (cachedlen >= filelen)) {
		cachednode = NULL;
		cachedlen = 0;
	}

	return do_find_insert_file(base, filename, filelen);
}

void update_parent_pointers(struct gr_learn_file_node *base)
{
	struct gr_learn_file_node *tmp;
	if (base->leaves == NULL)
		return;

	for_each_list_entry(tmp, base->leaves)
		tmp->parent = base;

	return;
}

void do_replace_file(struct gr_learn_file_node **base, struct gr_learn_file_node *replace)
{
	struct gr_learn_file_node *node;

	node = find_insert_file(base, replace->filename, strlen(replace->filename));

	assert(node != NULL);

	node->mode = replace->mode;
	node->dont_display = 0;

	assert(node->leaves == NULL);
	node->leaves = replace->leaves;

	assert(node->filename == NULL);
	node->filename = gr_strdup(replace->filename);

	/* important: we need to update all the parent pointers for these directly-linked nodes */
	update_parent_pointers(node);

	return;
}

void do_insert_file(struct gr_learn_file_node **base, char *filename, u_int32_t mode, u_int8_t subj)
{
	struct gr_learn_file_node *node;

	node = find_insert_file(base, filename, strlen(filename));

	assert(node != NULL);

	node->mode |= mode;
	node->dont_display = 0;

	if (node->filename == NULL)
		node->filename = gr_strdup(filename);

	if (subj)
		insert_file(&(node->object_list), "/", 0, 0);

	return;
}

void insert_file(struct gr_learn_file_node **base, char *filename, u_int32_t mode, u_int8_t subj)
{
	/* we're inserting a new file, and an entry for / does not exist, add it */
	if (!(*base)) {
		if (subj) {
			do_insert_file(base, "/", GR_PROCFIND, subj);
			if (subj == 2) /* learning in non-full mode, don't display / subject */
				(*base)->dont_display = 1;
		} else
			do_insert_file(base, "/", 0, subj);
	}

	do_insert_file(base, filename, mode, subj);

	return;
}

/* if this node has above the threshold number of leaves, then
   terminate each leaf at its next path component and reinsert them
   all as directories into the tree
   then, re-anchor each leaf to the newly created directory nodes

   this algorithm gets called against every node/leaf in the tree
*/

int first_reduce_node(struct gr_learn_file_node *node,
		       struct gr_learn_file_node *unused1, FILE *unused)
{
	unsigned long thresh = 5;	
	unsigned long num = count_nodes(node->leaves);
	struct gr_learn_file_node *tmp, *tmp2;
	char *p, *p2;
	unsigned int node_len = strlen(node->filename);
	int removed = 0;

	if (num < thresh)
		return 0;

	for_each_list_entry(tmp, node->leaves) {
		if (node_len == 1)
			p2 = strchr(tmp->filename + 1, '/');
		else
			p2 = strchr(tmp->filename + node_len + 1, '/');

		if (p2 == NULL)
			continue;

		p = gr_strdup(tmp->filename);
		*(p + (p2 - tmp->filename)) = '\0';
		cachednode = NULL;
		cachedlen = 0;
		insert_file(&node, p, 0, 0);
		free(p);
	}


	/* we're pulling out each leaf in this node and re-inserting it
	   we need to find where to insert the node, and then copy the unlinked
	   one in directly, preserving any attached leaves it may have
	*/
	for_each_removable_list_entry(tmp, node->leaves) {
		tmp = unlink_file_node_entry(tmp, &node->leaves, &tmp2);
		removed = 1;
		do_replace_file(&node, tmp2);
		free(tmp2->filename);
		gr_stat_free(tmp2);
		for_each_removable_list_entry_end(tmp);
	}

	return 0;
}

void first_stage_reduce_tree(struct gr_learn_file_node *base)
{
	return traverse_file_tree(base, &first_reduce_node, NULL, NULL);
}

void display_tree(struct gr_learn_file_node *base, FILE *stream)
{
	traverse_file_tree(base, &display_leaf, NULL, stream);
	return;
}

#ifdef GRADM_DEBUG
void check_high_protected_path_enforcement(struct gr_learn_file_node *subject)
{
	struct gr_learn_file_node *find;
	struct gr_learn_file_tmp_node **tmptable;
	char **tmp;
	unsigned int len;
	unsigned long i;

	tmp = high_protected_paths;
	if (tmp == NULL)
		return;

	tmptable = (struct gr_learn_file_tmp_node **)subject->hash->table;

	while (*tmp) {
		len = strlen(*tmp);
		for (i = 0; i < subject->hash->table_size; i++) {
			if (tmptable[i] == NULL)
				continue;
			if (!tmptable[i]->mode)
				continue;
			if (!strncmp(tmptable[i]->filename, *tmp, len) &&
			    (tmptable[i]->filename[len] == '\0' || tmptable[i]->filename[len] == '/'))
				goto next;
		}
		/* for all the ones that we didn't have a matching access from
		   the learning logs, find the object that matches us and make sure it's hidden
		*/
		find = find_file(subject->object_list, *tmp);
		assert(find != NULL);
		if (find->mode != 0)
			printf("Failed to enforce high-protected rule %s by object %s\n", *tmp, find->filename);
next:
		tmp++;
	}
	return;
}

void check_conformity_with_learned_rules(struct gr_learn_file_node *subject)
{
	struct gr_learn_file_node *tmp;
	struct gr_learn_file_tmp_node **tmptable;
	unsigned long i, table_size;

	tmptable = (struct gr_learn_file_tmp_node **)subject->hash->table;
	table_size = subject->hash->table_size;

	for (i = 0; i < table_size; i++) {
		if (tmptable[i] == NULL)
			continue;
		tmp = find_file(subject->object_list, tmptable[i]->filename);
		assert(tmp != NULL);
		if ((tmp->mode & tmptable[i]->mode) != tmptable[i]->mode)
			printf("Nonconformance detected in object %s with mode %x, %s requires %x\n", tmp->filename, tmp->mode, tmptable[i]->filename, tmptable[i]->mode);
	}

	return;
}

void check_file_node_list_integrity(struct gr_learn_file_node **filelist)
{
	struct gr_learn_file_node *node;
	unsigned int parentlen, ourlen;
	struct gr_learn_file_node *tmpnode;
	int i;

	if (*filelist == NULL)
		return;

	for_each_list_entry(node, *filelist) {
		check_file_node_list_integrity(&node->leaves);
		if (strcmp(node->filename, "/") && node->parent == NULL)
			goto inconsistency;
		else if (node->parent == NULL)
			goto ok;
		parentlen = strlen(node->parent->filename);
		ourlen = strlen(node->filename);
		if (parentlen >= ourlen)
			goto inconsistency;
		if (strncmp(node->filename, node->parent->filename, parentlen))
			goto inconsistency;
		if (parentlen != 1 && node->filename[parentlen] != '/')
			goto inconsistency;
		if (node->next && node->next->prev != node)
			goto inconsistency;
		if (node->prev && node->prev->next != node)
			goto inconsistency;
		tmpnode = node;
		i = 4096;
		while (tmpnode->parent && i) {
			tmpnode = tmpnode->parent;
			i--;
		}
		if (i == 0)
			goto inconsistency;
		goto ok;
inconsistency:
		printf("Inconsistency detected with file %s, parent %s\n", node->filename, node->parent ? node->parent->filename : "NULL");
ok:
		;
	}
	
}
#endif

int display_leaf(struct gr_learn_file_node *node,
		       struct gr_learn_file_node *unused1, FILE *stream)
{
	char modes[33];
	int i;

	if (node->dont_display)
		return 0;

	if (node->object_list) {
		struct gr_learn_file_node *object;
		struct gr_learn_ip_node *connect;
		struct gr_learn_ip_node *bind;
		unsigned int raise_num;

		object = node->object_list;
		connect = node->connect_list;
		bind = node->bind_list;
		conv_subj_mode_to_str(node->mode, modes, sizeof(modes));
		fprintf(stream, "subject %s %s {\n", node->filename, modes);

		if (node->user_trans_list) {
			unsigned int **p = node->user_trans_list;
			struct passwd *pwd;
			fprintf(stream, "user_transition_allow");
			while (*p) {
				pwd = getpwuid(**p);
				if (pwd == NULL) {
					fprintf(stream, " %d", **p);
					p++;
					continue;
				}
				fprintf(stream, " %s", pwd->pw_name);
				p++;
			}
			if (node->group_trans_list == NULL)
				fprintf(stream, "\n\n");
			else
				fprintf(stream, "\n");
		}

		if (node->group_trans_list) {
			unsigned int **p = node->group_trans_list;
			struct group *grp;
			fprintf(stream, "group_transition_allow");
			while (*p) {
				grp = getgrgid(**p);
				if (grp == NULL) {
					fprintf(stream, " %d", **p);
					p++;
					continue;
				}
				fprintf(stream, " %s", grp->gr_name);
				p++;
			}
			fprintf(stream, "\n\n");
		}

		if (object) {
			sort_file_node_list(object);
#ifdef GRADM_DEBUG
			check_file_node_list_integrity(&object->leaves);
			check_conformity_with_learned_rules(node);
			check_high_protected_path_enforcement(node);
#endif
			display_tree(object, stream);
		}
		if (!node->subject) {
			fprintf(stream, "\t-CAP_ALL\n");
			goto show_ips;
		}

		for(i = raise_num = 0; i < ((sizeof(capability_list)/sizeof(struct capability_set)) - 1); i++)
			if (cap_raised(node->subject->cap_raise, capability_list[i].cap_val))
				raise_num++;

		if (raise_num < ((sizeof(capability_list)/sizeof(struct capability_set)) - 1) / 2) {
			fprintf(stream, "\t-CAP_ALL\n");
			for(i = 0; i < ((sizeof(capability_list)/sizeof(struct capability_set)) - 1); i++)
				if (cap_raised(node->subject->cap_raise, capability_list[i].cap_val))
					fprintf(stream, "\t+%s\n", capability_list[i].cap_name);
		} else {
			fprintf(stream, "\t+CAP_ALL\n");
			for(i = 0; i < ((sizeof(capability_list)/sizeof(struct capability_set)) - 1); i++)
				if (!cap_raised(node->subject->cap_raise, capability_list[i].cap_val))
					fprintf(stream, "\t-%s\n", capability_list[i].cap_name);
		}

		for (i = 0; i < SIZE(paxflag_list); i++) {
			if (node->subject->pax_flags & (1 << paxflag_list[i].paxflag_val))
				fprintf(stream, "\t+%s\n", paxflag_list[i].paxflag_name);
			else if (node->subject->pax_flags & (0x8000 | (1 << paxflag_list[i].paxflag_val)))
				fprintf(stream, "\t-%s\n", paxflag_list[i].paxflag_name);
		}

		for(i = 0; i < SIZE(rlim_table); i++)
			if (node->subject->resmask & (1 << i))
				fprintf(stream, "\t%s %lu %lu\n", rlim_table[i],
					node->subject->res[i].rlim_cur,
					node->subject->res[i].rlim_max);

show_ips:
		if (bind)
			display_ip_tree(bind, GR_IP_BIND, stream);
		else
			fprintf(stream, "\tbind\tdisabled\n");
		if (connect)
			display_ip_tree(connect, GR_IP_CONNECT, stream);
		else
			fprintf(stream, "\tconnect\tdisabled\n");
		/* display socket families */
		if (node->subject != NULL) {
			int cnt = 0;
			for (i = 0; i < (SIZE(node->subject->sock_families) * 32); i++)
				if (node->subject->sock_families[i / 32] & (1 << (i % 32)))
					cnt++;
			/* if we have bind/connect rules and no extra family allowance outside of
			   the default, then don't add a sock_family rule
			*/
			if ((bind || connect) &&
				!(node->subject->sock_families[0] & ~((1 << AF_UNIX) | (1 << AF_LOCAL) | (1 << AF_INET))) &&
				node->subject->sock_families[1] == 0)
				;
			else if (cnt > 10)
				fprintf(stream, "\tsock_allow_family all\n");
			else if (cnt) {
				fprintf(stream, "\tsock_allow_family");
				for (i = 0; i < AF_MAX; i++) {
					if ((bind || connect) && (i == AF_UNIX || i == AF_LOCAL || i == AF_INET))
						continue;
					if (node->subject->sock_families[i / 32] & (1 << (i % 32)))
						fprintf(stream, " %s", get_sock_family_from_val(i));
				}
				fprintf(stream, "\n");
			}
		}
		if (node->subject != NULL && node->subject->inaddr_any_override) {
			struct in_addr addr;
			addr.s_addr = node->subject->inaddr_any_override;
			fprintf(stream, "\tip_override\t%s\n", inet_ntoa(addr));
		}

		fprintf(stream, "}\n\n");
	} else {
		conv_mode_to_str(node->mode, modes, sizeof(modes));
		i = strlen(node->filename);
		if (strchr(node->filename, ' ')) {
				if (i < 8)
					fprintf(stream, "\t\"%s\"\t\t\t\t%s\n", node->filename, modes);
				else if (i < 16)
					fprintf(stream, "\t\"%s\"\t\t\t%s\n", node->filename, modes);
				else if (i < 24)
					fprintf(stream, "\t\"%s\"\t\t%s\n", node->filename, modes);
				else
					fprintf(stream, "\t\"%s\"\t%s\n", node->filename, modes);
		} else {
			if (i < 8)
				fprintf(stream, "\t%s\t\t\t\t%s\n", node->filename, modes);
			else if (i < 16)
				fprintf(stream, "\t%s\t\t\t%s\n", node->filename, modes);
			else if (i < 24)
				fprintf(stream, "\t%s\t\t%s\n", node->filename, modes);
			else
				fprintf(stream, "\t%s\t%s\n", node->filename, modes);
		}
	}
	fflush(stream);
	return 0;
}

void traverse_ip_tree(struct gr_learn_ip_node *base,
		   struct gr_learn_ip_node **optarg,
		   int (*act)(struct gr_learn_ip_node *node, struct gr_learn_ip_node **optarg, u_int8_t contype, FILE *stream),
		   u_int8_t contype, FILE *stream)
{
	struct gr_learn_ip_node *node;

	if (!base)
		return;

	act(base, optarg, contype, stream);
	
	for_each_list_entry(node, base->leaves)
		traverse_ip_tree(node, optarg, act, contype, stream);

	return;
}

int count_ip_depth(struct gr_learn_ip_node *node)
{
	int depth = 0;

	for_each_parent_entry(node, node->parent)
		depth++;

	return depth;
}

unsigned long count_total_ips(struct gr_learn_ip_node *node)
{
	unsigned long ips = 0;
	struct gr_learn_ip_node *tmp;

	if (node->leaves == NULL)
		return 1;

	for_each_list_entry(tmp, node->leaves)
		ips += count_total_ips(tmp);

	return ips;
}
	

int display_ip_node(struct gr_learn_ip_node *node, struct gr_learn_ip_node **unused, u_int8_t contype,
		    FILE *stream)
{
	struct gr_learn_ip_node *saved = node;
	int depth = count_ip_depth(node);
	u_int16_t **tmpport;
	u_int8_t ip[4];
	char ipandtype[64] = {0};
	char socktypeandprotos[4096] = {0};
	struct protoent *proto;
	int netmask = 0;
	int i;

	if (node->leaves)
		return 0;

	if (!node->root_node)
		netmask = 8 * depth;
	else {
		ip[0] = ip[1] = ip[2] = ip[3] = 0;
		goto print_ip;
	}

	for(i = 3; i >= 0; i--) {
		if (depth < (i + 1))
			ip[i] = 0;
		else {
			ip[i] = node->ip_node;
			node = node->parent;
		}
	}

print_ip:
	node = saved;
	if (contype == GR_IP_CONNECT)
		sprintf(ipandtype, "\tconnect %u.%u.%u.%u/%u", ip[0], ip[1], ip[2], ip[3], netmask);
	else if (contype == GR_IP_BIND)
		sprintf(ipandtype, "\tbind %u.%u.%u.%u/%u", ip[0], ip[1], ip[2], ip[3], netmask);

	for (i = 1; i < 5; i++) {
		if (node->ip_type & (1 << i)) {
			switch (i) {
			case SOCK_RAW:
				strcat(socktypeandprotos, " raw_sock");
				break;
			case SOCK_DGRAM:
				strcat(socktypeandprotos, " dgram");
				break;
			case SOCK_STREAM:
				strcat(socktypeandprotos, " stream");
				break;
			case SOCK_RDM:
				strcat(socktypeandprotos, " rdm");
				break;
			}
		}
	}

	for (i = 0; i < 256; i++) {
		if (node->ip_proto[i / 32] & (1 << (i % 32))) {
			if (i == IPPROTO_RAW) {
				strcat(socktypeandprotos, " raw_proto");
			} else {
				proto = getprotobynumber(i);
				strcat(socktypeandprotos, " ");
				strcat(socktypeandprotos, proto->p_name);
			}
		}
	}

	if (node->all_low_ports && node->all_high_ports)
		fprintf(stream, "%s:0-65535%s\n", ipandtype, socktypeandprotos);
	else if (node->all_low_ports)
		fprintf(stream, "%s:0-1023%s\n", ipandtype, socktypeandprotos);
	else if (node->all_high_ports)
		fprintf(stream, "%s:1024-65535%s\n", ipandtype, socktypeandprotos);

	tmpport = node->ports;

	while(tmpport && *tmpport) {
		if (!(node->all_low_ports && **tmpport < 1024) &&
		    !(node->all_high_ports && **tmpport >= 1024))
			fprintf(stream, "%s:%u%s\n", ipandtype, **tmpport, socktypeandprotos);
		tmpport++;
	}

	return 0;
}

int display_only_ip(struct gr_learn_ip_node *node, struct gr_learn_ip_node **unused, u_int8_t unused2,
		    FILE *stream)
{
	struct gr_learn_ip_node *saved = node;
	int depth = count_ip_depth(node);
	u_int8_t ip[4];
	int netmask = 0;
	int i;

	if (node->leaves)
		return 0;

	if (!node->root_node)
		netmask = 8 * depth;
	else {
		ip[0] = ip[1] = ip[2] = ip[3] = 0;
		goto print_ip;
	}

	for(i = 3; i >= 0; i--) {
		if (depth < (i + 1))
			ip[i] = 0;
		else {
			ip[i] = node->ip_node;
			node = node->parent;
		}
	}

print_ip:
	node = saved;
	fprintf(stream, "role_allow_ip\t%u.%u.%u.%u/%u\n", ip[0], ip[1], ip[2], ip[3], netmask);

	return 0;
}

void display_ip_tree(struct gr_learn_ip_node *base, u_int8_t contype, FILE *stream)
{
	traverse_ip_tree(base, NULL, &display_ip_node, contype, stream);
	return;
}

unsigned long count_ports(u_int16_t **ports)
{
	unsigned long ret = 0;

	if (!ports)
		return ret;

	while (*ports) {
		ports++;
		ret++;
	}

	return ret;
}		
		
unsigned long count_ips(struct gr_learn_ip_node *ips)
{
	unsigned long ret = 0;
	struct gr_learn_ip_node *tmp;

	for_each_list_entry(tmp, ips)
		ret++;

	return ret;
}

int analyze_ip_node(struct gr_learn_ip_node *node)
{
	int depth = count_ip_depth(node);
	unsigned long num_ips = count_total_ips(node);
	unsigned long analysis_factor = (depth + 1) * num_ips;

	if (analysis_factor > 19)
		return 1;
	else
		return 0;
}

void insert_port(struct gr_learn_ip_node *node, u_int16_t port)
{
	u_int16_t **tmpport;
	unsigned long num;

	tmpport = node->ports;

	num = count_ports(tmpport);

	while(tmpport && *tmpport) {
		if (**tmpport == port)
			return;
		tmpport++;
	}

	if (!num) {
		node->ports = (u_int16_t **)gr_dyn_alloc(2 * sizeof(u_int16_t *));
		*(node->ports) = (u_int16_t *)gr_stat_alloc(sizeof(u_int16_t));
		**(node->ports) = port;
	} else {
		node->ports = (u_int16_t **)gr_dyn_realloc(node->ports, (num + 2) * sizeof(u_int16_t *));
		memset(node->ports + num, 0, 2 * sizeof(u_int16_t *));
		*(node->ports + num) = (u_int16_t *)gr_stat_alloc(sizeof(u_int16_t));
		**(node->ports + num) = port;
	}

	return;
}

void remove_port(struct gr_learn_ip_node *node, u_int16_t port)
{
	u_int16_t **ports = node->ports;
	unsigned long num = count_ports(ports);
	unsigned long i;

	for(i = 0; i < num; i++) {
		if (**(ports + i) == port) {
			gr_stat_free(*(ports + i));
			while (i < num) {
				**(ports + i) = **(ports + i + 1);
				i++;
			}
		}
	}

	return;
}

void do_reduce_ip_node(struct gr_learn_ip_node *node, struct gr_learn_ip_node *actor)
{
	u_int16_t **tmpport = node->ports;
	struct gr_learn_ip_node *tmpip;
	int i;
	int removed = 0;

	while (tmpport && *tmpport) {
		insert_port(actor, **tmpport);
		gr_stat_free(*tmpport);
		*tmpport = NULL;
		tmpport++;
	}
	if (node->ports) {
		gr_dyn_free(node->ports);
		node->ports = NULL;
	}

	for (i = 0; i < (sizeof(node->ip_proto)/sizeof(node->ip_proto[0])); i++)
		actor->ip_proto[i] |= node->ip_proto[i];
	actor->ip_type |= node->ip_type;

	for_each_removable_list_entry(tmpip, node->leaves) {
		do_reduce_ip_node(tmpip, actor);
		tmpip = unlink_and_free_ip_node_entry(tmpip, &node->leaves);
		removed = 1;
		for_each_removable_list_entry_end(tmpip);
	}

	node->leaves = NULL;

	return;
}



int reduce_ip_node(struct gr_learn_ip_node *node, struct gr_learn_ip_node **actor, u_int8_t unused1,
		   FILE *unused2)
{
	
	if (analyze_ip_node(node)) {
		*actor = node;
		do_reduce_ip_node(node, *actor);
	}

	return 0;
}

int analyze_port_node(struct gr_learn_ip_node *node)
{
	unsigned long low_ports = 0, high_ports = 0;
	int ret = 0;
	u_int16_t **tmpport;

	tmpport = node->ports;

	while (tmpport && *tmpport) {
		if (**tmpport < 1024)
			low_ports++;
		else
			high_ports++;
		tmpport++;
	}

	if (low_ports > 5)
		ret += 1;
	if (high_ports > 4)
		ret += 2;

	return ret;
}	

int reduce_port_node(struct gr_learn_ip_node *node, struct gr_learn_ip_node **unused, u_int8_t unused1,
		     FILE *unused2)
{
	
	switch(analyze_port_node(node)) {
	case 1:
		node->all_low_ports = 1;
		break;
	case 2:
		node->all_high_ports = 1;
		break;
	case 3:
		node->all_low_ports = 1;
		node->all_high_ports = 1;
		break;
	}

	return 0;
}


void reduce_ip_tree(struct gr_learn_ip_node *base)
{
	struct gr_learn_ip_node *tmp = NULL;

	traverse_ip_tree(base, &tmp, &reduce_ip_node, 0, NULL);
	return;
}

void reduce_ports_tree(struct gr_learn_ip_node *base)
{
	traverse_ip_tree(base, NULL, &reduce_port_node, 0, NULL);
	return;
}

u_int8_t extract_ip_field(u_int32_t ip, unsigned long depth)
{
	u_int8_t ip_node[4];

	memcpy(ip_node, &ip, sizeof(ip));

	if (depth > 3)
		return 0;

	return ip_node[depth];
}

struct gr_learn_ip_node * find_insert_ip(struct gr_learn_ip_node **base, u_int32_t ip)
{
	struct gr_learn_ip_node *node, *tmpip, *newip;
	int depth = 0;
	int match = 0;

	if (!(*base)) {
		(*base) = (struct gr_learn_ip_node *)gr_stat_alloc(sizeof(struct gr_learn_ip_node));
		(*base)->root_node = 1;
	}

	depth = count_ip_depth(*base);
	node = (*base)->leaves;

	for_each_list_entry(tmpip, node) {
		if (tmpip->ip_node == extract_ip_field(ip, depth)) {
			match = 1;
			break;
		}
	}

	if (match && depth < 3) {
		/* partial match, try to match at the next depth */
		return find_insert_ip(&tmpip, ip);
	} else if (match) {
		/* complete match, return it */
		return tmpip;
	} else {
		/* no match, need to allocate a new node */
		newip = (struct gr_learn_ip_node *)gr_stat_alloc(sizeof(struct gr_learn_ip_node));
		newip->parent = *base;
		newip->ip_node = extract_ip_field(ip, depth);

		establish_new_head((*base)->leaves, newip, tmpip);

		if (depth < 3)
			return find_insert_ip(&newip, ip);
		else
			return newip;
	}
}

void insert_ip(struct gr_learn_ip_node **base, u_int32_t ip, u_int16_t port, u_int8_t proto,
		u_int8_t socktype)
{
	struct gr_learn_ip_node *node;

	node = find_insert_ip(base, ip);

	/* the IP has already been added to the tree,
	   so just OR in the information we've filled out in the
	   insert structure */
	node->ip_proto[proto / 32] |= (1 << (proto % 32));
	node->ip_type |= (1 << socktype);
	insert_port(node, port);

	return;
}

static int strcompare(const void *x, const void *y)
{
        const struct gr_learn_file_tmp_node *x1 = *(const struct gr_learn_file_tmp_node * const *) x;
        const struct gr_learn_file_tmp_node *y1 = *(const struct gr_learn_file_tmp_node * const *) y;

	if (x1 == NULL && y1 == NULL)
		return 0;
	if (x1 == NULL && y1 != NULL)
		return 1;
	if (x1 != NULL && y1 == NULL)
		return -1;
        return strcmp(x1->filename, y1->filename);
}

/* use this function to operate on a hash table, thus we need to handle
   null entries in the table.  we modify strcompare above to make null
   pointers lexicographically greater than all filenames, effectively
   pushing them to the end of the table
*/

void sort_file_list(struct gr_hash_struct *hash)
{
	if (hash == NULL)
		return;

	return qsort(hash->table, hash->table_size, sizeof (struct gr_learn_file_tmp_node *), strcompare);
}

struct gr_learn_file_tmp_node *conv_filename_to_struct(char *filename, u_int32_t mode)
{
	struct gr_learn_file_tmp_node *node;

	node = (struct gr_learn_file_tmp_node *)gr_stat_alloc(sizeof(struct gr_learn_file_tmp_node));
	node->filename = gr_strdup(filename);
	node->mode = mode;

	return node;
}

struct gr_learn_role_entry *
insert_learn_role(struct gr_learn_role_entry **role_list, char *rolename, u_int16_t rolemode)
{
	struct gr_learn_role_entry *tmp;
	struct gr_learn_role_entry *newrole;
	
	for_each_list_entry(tmp, *role_list) {
		if (!strcmp(tmp->rolename, rolename)) {
			tmp->rolemode |= rolemode;
			return tmp;
		}
	}

	newrole = (struct gr_learn_role_entry *)gr_stat_alloc(sizeof(struct gr_learn_role_entry));
	newrole->rolename = gr_strdup(rolename);
	newrole->rolemode = rolemode;

	establish_new_head(*role_list, newrole, tmp);

	/* give every learned role a / subject */
	insert_learn_role_subject(newrole, conv_filename_to_struct("/", GR_PROCFIND | GR_OVERRIDE));

	return newrole;
}

struct gr_learn_role_entry *
find_learn_role(struct gr_learn_role_entry *role_list, char *rolename)
{
	struct gr_learn_role_entry *tmp;

	for_each_list_entry(tmp, role_list) {
		if (!strcmp(tmp->rolename, rolename))
			return tmp;
	}

	return NULL;
}

void insert_learn_id_transition(unsigned int ***list, int real, int eff, int fs)
{
	unsigned int ids[] = { real, eff, fs };
	int x, good, num;
	unsigned int **p;

	if (*list == NULL)
		*list = (unsigned int **)gr_dyn_alloc(2 * sizeof(unsigned int *));


	for (x = 0; x < sizeof(ids)/sizeof(ids[0]); x++) {
		good = 1;
		if (ids[x] == -1)
			good = 0;
		for (p = *list; *p; p++) {
			if (ids[x] == **p)
				good = 0;
		}
		if (good) {
			p = *list;
			num = 0;
			while (*p) {
				p++;
				num++;
			}
			*list = (unsigned int **)gr_dyn_realloc(*list, (num + 2) * sizeof(unsigned int *));
			memset(*list + num, 0, 2 * sizeof(unsigned int *));
			*(*list + num) = (unsigned int *)gr_stat_alloc(sizeof(unsigned int));
			**(*list + num) = ids[x];
		}
	}

	return;
}
