#include "gradm.h"

struct gr_learn_file_node **cachednode = NULL;
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

void match_role(struct gr_learn_group_node **grouplist, uid_t uid, gid_t gid, struct gr_learn_group_node **group,
		struct gr_learn_user_node **user)
{
	struct gr_learn_group_node **tmpgroup;
	struct gr_learn_user_node **tmpuser;

	*group = NULL;
	*user = NULL;

	tmpgroup = grouplist;

	if (!tmpgroup)
		return;

	while (*tmpgroup) {
		tmpuser = (*tmpgroup)->users;
		while (tmpuser && *tmpuser) {
			if ((*tmpuser)->uid == uid) {
				*user = *tmpuser;
				return;
			}
			tmpuser++;
		}
		tmpgroup++;
	}

	tmpgroup = grouplist;

	while (*tmpgroup) {
		if ((*tmpgroup)->gid == gid) {
			*group = *tmpgroup;
			return;
		}
		tmpgroup++;
	}
				
	return;
}

void traverse_roles(struct gr_learn_group_node **grouplist, 
		    int (*act)(struct gr_learn_group_node *group, struct gr_learn_user_node *user, FILE *stream),
		    FILE *stream)
{
	struct gr_learn_group_node **tmpgroup;
	struct gr_learn_user_node **tmpuser;

	tmpgroup = grouplist;

	if (!tmpgroup)
		return;

	while(*tmpgroup) {
		tmpuser = (*tmpgroup)->users;
		if (!tmpuser)
			act(*tmpgroup, NULL, stream);
		else {
			while(*tmpuser) {
				act(*tmpgroup, *tmpuser, stream);
				tmpuser++;
			}
		}
		tmpgroup++;
	}

	return;
}

int display_role(struct gr_learn_group_node *group, struct gr_learn_user_node *user, FILE *stream)
{
	struct gr_learn_file_node *subject = NULL;

	output_role_info(group, user, stream);

	if (user)
		subject = user->subject_list;
	else
		subject = group->subject_list;

	if (subject)
		display_tree(subject, stream);

	fprintf(stream, "\n");

	return 0;
}

void display_roles(struct gr_learn_group_node **grouplist, FILE *stream)
{
	output_learn_header(stream);
	traverse_roles(grouplist, &display_role, stream);
	return;
}
	
struct gr_learn_group_node **find_insert_group(struct gr_learn_group_node ***grouplist, gid_t gid)
{
	struct gr_learn_group_node **tmp = *grouplist;
	unsigned long num = 0;

	if (!tmp) {
		*grouplist = (struct gr_learn_group_node **)gr_dyn_alloc(2 * sizeof(struct gr_learn_group_node *));
		return (*grouplist);
	}

	while(*tmp) {
		if ((*tmp)->gid == gid)
			return tmp;
		tmp++;
		num++;
	}

	*grouplist = (struct gr_learn_group_node **)gr_dyn_realloc(*grouplist, (num + 2) * sizeof(struct gr_learn_group_node *));
	memset(*grouplist + num, 0, 2 * sizeof(struct gr_learn_group_node *));
 
	return (*grouplist + num);
}

unsigned long count_users(struct gr_learn_group_node *group)
{
	struct gr_learn_user_node **tmp;
	unsigned long ret = 0;

	tmp = group->users;

	if (!tmp)
		return 0;

	while (*tmp) {
		ret++;
		tmp++;
	}

	return ret;
}

static unsigned long count_users_nomultgroups(struct gr_learn_group_node *group)
{
	struct gr_learn_user_node **tmp;
	unsigned long ret = 0;

	tmp = group->users;

	if (!tmp)
		return 0;

	while (*tmp) {
		if (!(*tmp)->multgroups)
			ret++;
		tmp++;
	}

	return ret;
}

void insert_user(struct gr_learn_group_node ***grouplist, char *username, char *groupname, uid_t uid, gid_t gid)
{
	struct gr_learn_group_node **group;
	struct gr_learn_user_node **tmpuser;
	unsigned long num;
	int multgroups = 0;

	/* first check to see if the user exists in any group */

	group = *grouplist;
	while (group && *group) {
		tmpuser = (*group)->users;
		while (tmpuser && *tmpuser) {
			/* found them, check if we've noted the group membership observed */
			if ((*tmpuser)->uid == uid) {
				/* user belongs to multiple groups, don't use them for reduction */
				if ((*tmpuser)->group->gid != gid) {
					(*tmpuser)->multgroups = 1;
					multgroups = 1;
				} else /* this entry is a duplicate */
					return;
			}
			tmpuser++;
		}
		group++;
	}

	group = find_insert_group(grouplist, gid);

	if (*group) {
		num = count_users(*group);

		(*group)->users = (struct gr_learn_user_node **)gr_dyn_realloc((*group)->users, (num + 2) * sizeof(struct gr_learn_user_node *));
		memset((*group)->users + num, 0, 2 * sizeof(struct gr_learn_user_node *));

		tmpuser = ((*group)->users + num);
		*tmpuser = (struct gr_learn_user_node *)gr_stat_alloc(sizeof(struct gr_learn_user_node));
		(*tmpuser)->rolename = gr_strdup(username);
		(*tmpuser)->uid = uid;
		(*tmpuser)->group = *group;
		(*tmpuser)->multgroups = multgroups;
	} else {
		*group = (struct gr_learn_group_node *)gr_stat_alloc(sizeof(struct gr_learn_group_node));
		(*group)->rolename = gr_strdup(groupname);
		(*group)->gid = gid;
		(*group)->users = (struct gr_learn_user_node **)gr_dyn_alloc(2 * sizeof(struct gr_learn_user_node *));
		tmpuser = (*group)->users;
		*tmpuser = (struct gr_learn_user_node *)gr_stat_alloc(sizeof(struct gr_learn_user_node));
		(*tmpuser)->rolename = gr_strdup(username);
		(*tmpuser)->uid = uid;
		(*tmpuser)->group = *group;
		(*tmpuser)->multgroups = multgroups;
	}

	return;
}

void reduce_roles(struct gr_learn_group_node ***grouplist)
{
	unsigned int thresh = 3;
	struct gr_learn_group_node **group = *grouplist, **group2, **group3;
	struct gr_learn_user_node **tmpuser, **tmpuser2;
	unsigned long num;

	while (group && *group) {
		num = count_users_nomultgroups(*group);
		if (num >= thresh) {
			tmpuser = (*group)->users;
			while(*tmpuser) {
				free((*tmpuser)->rolename);
				gr_stat_free(*tmpuser);
				*tmpuser = NULL;
				tmpuser++;
			}
			gr_dyn_free((*group)->users);
			(*group)->users = NULL;
		}
		group++;
	}
	
	/* make sure only one role is created for each user */
	group = *grouplist;
	while (group && *group) {
		tmpuser = (*group)->users;
		while(tmpuser && *tmpuser) {
			if ((*tmpuser)->multgroups) {
				/* check to see if the user is in another group,
				   and remove them from this group if so */
				group2 = group + 1;
				while (*group2) {
					tmpuser2 = (*group2)->users;
					while (tmpuser2 && *tmpuser2) {
						if ((*tmpuser2)->uid == (*tmpuser)->uid) {
							free((*tmpuser2)->rolename);
							gr_stat_free(*tmpuser2);
							while (*tmpuser2) {
								*tmpuser2 = *(tmpuser2 + 1);
								tmpuser2++;
							}
							/* we removed the only user in this group, so remove
							   the group as well
							*/
							if (*((*group2)->users) == NULL) {
								gr_dyn_free((*group2)->users);
								free((*group2)->rolename);
								gr_stat_free(*group2);
								group3 = group2;
								while (*group3) {
									*group3 = *(group3 + 1);
									group3++;
								}
								/* since we removed a group, the next group to check is the 
								   one currently pointed to by group2 */
								group2--;
							}
							goto done;
						}
						tmpuser2++;
					}
done:
					group2++;
				}
			}
			tmpuser++;
		}
		group++;
	}

	return;
}

void traverse_file_tree(struct gr_learn_file_node *base,
		   int (*act)(struct gr_learn_file_node *node, struct gr_learn_file_node *optarg, FILE *stream),
		   struct gr_learn_file_node *optarg, FILE *stream)
{
	struct gr_learn_file_node **node;

	if (!base)
		return;

	act(base, optarg, stream);

	node = base->leaves;

	if (!node)
		return;

	while(*node) {
		traverse_file_tree(*node, act, optarg, stream);
		node++;
	}

	return;
}

struct gr_learn_file_node *match_file_node(struct gr_learn_file_node *base,
					const char *filename)
{
	struct gr_learn_file_node **node, *ret;
	unsigned int baselen, filelen;

	filelen = strlen(filename);

	if (!base)
		return base;

	baselen = strlen(base->filename);
	if ((filelen == baselen) && !strcmp(base->filename, filename))
		return base;

	if ((baselen >= filelen) || (filename[baselen] != '/' && baselen != 1) ||
	    strncmp(base->filename, filename, baselen))
		return NULL;

	node = base->leaves;

	if (!node)
		return base;

	while(*node) {
		if ((ret = match_file_node(*node, filename)))
			return ret;
		node++;
	}
	
	return base;
}

unsigned long count_nodes(struct gr_learn_file_node **node)
{
	unsigned long ret = 0;

	if (!node)
		return 0;

	while(*node) {
		ret++;
		node++;
	}

	return ret;
}

unsigned long count_leaf_nodes(struct gr_learn_file_node **node)
{
	unsigned long ret = 0;

	if (!node)
		return 0;

	while(*node) {
		if (!((*node)->leaves))
			ret++;
		node++;
	}

	return ret;
}

unsigned long count_total_leaves(struct gr_learn_file_node *node)
{
	unsigned long leaves = 0;
	struct gr_learn_file_node **tmp;

	tmp = node->leaves;
	if (!tmp)
		return 0;

	while(*tmp) {
		leaves++;
		leaves += count_total_leaves(*tmp);
		tmp++;
	}

	return leaves;
}

unsigned long count_max_depth(struct gr_learn_file_node *node)
{
	unsigned long max = 0, tmpmax = 0;
	struct gr_learn_file_node **tmp;

	tmp = node->leaves;
	if (!tmp)
		return 0;

	max++;
	while(*tmp) {
		tmpmax = count_max_depth(*tmp);
		if ((max + tmpmax) > max)
			max = tmpmax + max;
		tmp++;
	}

	return max;
}	

unsigned long count_nested_depth(struct gr_learn_file_node *node)
{
	unsigned long depth = 0;
	struct gr_learn_file_node *tmp;

	tmp = node->parent;
	if (!tmp)
		return 0;

	while(tmp) {
		depth++;
		tmp = tmp->parent;
	}

	return depth;
}	

int reduce_all_children(struct gr_learn_file_node *node)
{
	unsigned long num, not_leaf = 0;
	unsigned long i, j;
	struct gr_learn_file_node **tmp;
	
	tmp = node->leaves;
	num = 0;
	while (*tmp) {
		if (!((*tmp)->leaves)) {
			node->mode |= (*tmp)->mode;
			if (node->subject && (*tmp)->subject) {
				node->subject->cap_raise = cap_combine(node->subject->cap_raise, 
								       (*tmp)->subject->cap_raise);
				node->subject->resmask |= (*tmp)->subject->resmask;
				for (i = 0; i < GR_NLIMITS; i++) {
					if ((*tmp)->subject->res[i].rlim_cur > node->subject->res[i].rlim_cur)
						node->subject->res[i].rlim_cur = (*tmp)->subject->res[i].rlim_cur;
					if ((*tmp)->subject->res[i].rlim_max > node->subject->res[i].rlim_max)
						node->subject->res[i].rlim_max = (*tmp)->subject->res[i].rlim_max;
				}
			}
		} else
			not_leaf++;
		tmp++;
		num++;
	}

	tmp = node->leaves;
	for (i = 0; i < num; i++) {
		if (*(tmp + i) && !(*(tmp + i))->leaves) {
			cachednode = NULL;
			cachedlen = 0;
			free((*(tmp + i))->filename);
			gr_stat_free(*(tmp + i));
			j = i;
			while (*(tmp + j + 1)) {
				*(tmp + j) = *(tmp + j + 1);
				j++;
			}
			*(tmp + j) = NULL;			
		}
	}

	if (!not_leaf) {
		gr_dyn_free(node->leaves);
		node->leaves = NULL;
		return 0;
	}

	return 0;
}

int reduce_all_leaves(struct gr_learn_file_node *node)
{
	struct gr_learn_file_node **tmp;
	unsigned int i;

	tmp = node->leaves;
	if (!tmp)
		return 0;
	while (*tmp) {
		reduce_all_leaves(*tmp);
		node->mode |= (*tmp)->mode;
		if (node->subject && (*tmp)->subject) {
			node->subject->cap_raise = cap_combine(node->subject->cap_raise,
							       (*tmp)->subject->cap_raise);
			node->subject->resmask |= (*tmp)->subject->resmask;
			for (i = 0; i < GR_NLIMITS; i++) {
				if ((*tmp)->subject->res[i].rlim_cur > node->subject->res[i].rlim_cur)
					node->subject->res[i].rlim_cur = (*tmp)->subject->res[i].rlim_cur;
				if ((*tmp)->subject->res[i].rlim_max > node->subject->res[i].rlim_max)
					node->subject->res[i].rlim_max = (*tmp)->subject->res[i].rlim_max;
			}
		}
		cachednode = NULL;
		cachedlen = 0;
		free((*tmp)->filename);
		gr_stat_free(*tmp);
		*tmp = NULL;
		tmp++;
	}

	gr_dyn_free(node->leaves);
	node->leaves = NULL;

	return 0;
}

void greatest_occurring_modes(struct gr_learn_file_node *node, u_int32_t *modeary)
{
	struct gr_learn_file_node **tmp;
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

	tmp = node->leaves;

	while (*tmp) {
		for (i = 0; i < 12; i++) {
			if ((*tmp)->mode == modes[i])
				counts[i]++;
		}

		tmp++;
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
	struct gr_learn_file_node **tmp;
	struct gr_learn_file_node **tmp2;
	u_int32_t modes[2];
	int ret = 0;
	int tmpdir = 0;

	tmp = node->leaves;
	if (!tmp)
		return 0;
	
	greatest_occurring_modes(node, (u_int32_t *)&modes);

	node->mode |= modes[0];
	node->mode |= modes[1];

	if (node->mode == (GR_FIND | GR_READ | GR_WRITE | GR_CREATE | GR_DELETE))
		tmpdir = 1;

	while (*tmp) {
		if (((tmpdir && !((*tmp)->mode & GR_EXEC)) ||
		     ((*tmp)->mode == modes[0] || (*tmp)->mode == modes[1]))
		    && !(*tmp)->leaves) {
			tmp2 = tmp;
			cachednode = NULL;
			cachedlen = 0;
			ret++;
			free((*tmp)->filename);
			gr_stat_free(*tmp);
			while (*(tmp2 + 1)) {
				*(tmp2) = *(tmp2 + 1);
				tmp2++;
			}
			*tmp2 = NULL;
		} else
			tmp++;
	}

	return ret;
}

int analyze_node_read_permissions(struct gr_learn_file_node *node)
{
	struct gr_learn_file_node **tmp;

	if (!node->leaves)
		return 1;

	tmp = node->leaves;

	while (*tmp) {
		if (((*tmp)->mode & GR_WRITE) && !((*tmp)->mode & GR_READ))
			return 0;
		if (!analyze_node_read_permissions(*tmp))
			return 0;
		tmp++;
	}

	return 1;
}

int analyze_node_write_permissions(struct gr_learn_file_node *node)
{
	struct gr_learn_file_node **tmp;

	if (!node->leaves)
		return 1;

	tmp = node->leaves;

	while (*tmp) {
		if (!((*tmp)->mode & GR_WRITE) && ((*tmp)->mode & GR_READ))
			return 0;
		if (!analyze_node_write_permissions(*tmp))
			return 0;
		tmp++;
	}

	return 1;
}

int analyze_child_read_permissions(struct gr_learn_file_node *node)
{
	struct gr_learn_file_node **tmp;

	if (!node->leaves)
		return 1;

	tmp = node->leaves;

	while (*tmp) {
		if ((*tmp)->leaves) {
			tmp++;
			continue;
		}
		if (((*tmp)->mode & GR_WRITE) && !((*tmp)->mode & GR_READ))
			return 0;
		tmp++;
	}

	return 1;
}

int analyze_child_write_permissions(struct gr_learn_file_node *node)
{
	struct gr_learn_file_node **tmp;

	if (!node->leaves)
		return 1;

	tmp = node->leaves;

	while (*tmp) {
		if ((*tmp)->leaves) {
			tmp++;
			continue;
		}
		if (!((*tmp)->mode & GR_WRITE) && ((*tmp)->mode & GR_READ))
			return 0;
		tmp++;
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

	if (!node->leaves)
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
	struct gr_learn_file_node **tmp, **tmp2;

	tmp = node->leaves;

	if (!tmp)
		return 0;

	while (*tmp) {
		if ((*tmp)->leaves) {
			tmp++;
			continue;
		}
		if ((*tmp)->mode == node->mode ||
		    (((node->mode & (GR_WRITE | GR_CREATE)) == (GR_WRITE | GR_CREATE)) &&
		    ((*tmp)->mode & GR_WRITE))) {
			node->mode |= (*tmp)->mode;
			tmp2 = tmp;
			cachednode = NULL;
			cachedlen = 0;
			free((*tmp)->filename);
			gr_stat_free(*tmp);
			while(*(tmp2 + 1)) {
				*tmp2 = *(tmp2 + 1);
				tmp2++;
			}
			*tmp2 = NULL;
		} else
			tmp++;
	}

	return 0;
}	
		

void third_stage_reduce_tree(struct gr_learn_file_node *base)
{
	return traverse_file_tree(base, &third_reduce_node, NULL, NULL);
}

struct gr_learn_file_node **do_find_insert_file(struct gr_learn_file_node **base,
					struct gr_learn_file_node *insert, unsigned int filelen,
					struct gr_learn_file_node **parent)
{
	struct gr_learn_file_node **node, **tmpnode, **ret;
	unsigned int baselen;
	unsigned long num_leaves;

	if (!*base) {
		*parent = *base;
		return base;
	}

	baselen = strlen((*base)->filename);
	if ((filelen == baselen) && !strcmp((*base)->filename, insert->filename))
		return base;

	node = (*base)->leaves;

	if (!node && (baselen < filelen) && (baselen == 1 || insert->filename[baselen] == '/') &&
	    !strncmp((*base)->filename, insert->filename, baselen)) {
		*parent = *base;
		(*base)->leaves = node = (struct gr_learn_file_node **)gr_dyn_alloc(2 * sizeof(struct gr_learn_file_node *));
		cachednode = base;
		cachedlen = baselen;
		return node;
	} else if (!node)
		return NULL;

	tmpnode = node;

	while(*tmpnode) {
		ret = do_find_insert_file(tmpnode, insert, filelen, parent);
		if (ret)
			return ret;
		tmpnode++;
	}
	
	if ((baselen >= filelen) || (baselen != 1 && insert->filename[baselen] != '/') ||
	    strncmp((*base)->filename, insert->filename, baselen)) 
		return NULL;

	*parent = *base;
	num_leaves = count_nodes(node);
	(*base)->leaves = node = (struct gr_learn_file_node **)gr_dyn_realloc((*base)->leaves, (num_leaves + 2) * sizeof(struct gr_learn_file_node *));
	cachednode = base;
	cachedlen = baselen;
	memset(node + num_leaves, 0, 2 * sizeof(struct gr_learn_file_node *));
	return (node + num_leaves);
}

struct gr_learn_file_node **find_insert_file(struct gr_learn_file_node **base,
					struct gr_learn_file_node *insert, unsigned int filelen,
					struct gr_learn_file_node **parent)
{
	if (cachednode && *cachednode && (cachedlen < filelen) && !strncmp((*cachednode)->filename, insert->filename, cachedlen)
	    && insert->filename[cachedlen] == '/') {
		return do_find_insert_file(cachednode, insert, filelen, parent);
	} else if (cachednode && *cachednode && (cachedlen >= filelen)) {
		cachednode = NULL;
		cachedlen = 0;
	}

	return do_find_insert_file(base, insert, filelen, parent);
}



void do_insert_file(struct gr_learn_file_node **base, char *filename, u_int32_t mode, u_int8_t subj)
{
	struct gr_learn_file_node **node;
	struct gr_learn_file_node *parent = NULL;
	struct gr_learn_file_node *insert;

	insert = (struct gr_learn_file_node *)gr_stat_alloc(sizeof(struct gr_learn_file_node));

	insert->filename = gr_strdup(filename);
	insert->mode = mode;

	if (subj)
		insert_file(&(insert->object_list), "/", 0, 0);		

	node = find_insert_file(base, insert, strlen(filename), &parent);

	if (*node) {
		(*node)->mode |= mode;
		(*node)->dont_display = 0;
		free(insert->filename);
		gr_stat_free(insert);
		return;
	} else {
		*node = insert;
		(*node)->parent = parent;
	}

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

int first_reduce_node(struct gr_learn_file_node *node,
		       struct gr_learn_file_node *unused1, FILE *unused)
{
	unsigned long thresh = 5;	
	unsigned long cnt = 0;
	unsigned long num = count_nodes(node->leaves);
	struct gr_learn_file_node **tmp, **tmp2, **tmp3, *tmp4;
	struct gr_learn_file_node *parent = NULL;
	char *p, *p2;
	unsigned int node_len = strlen(node->filename);

	if (num < thresh)
		return 0;

	tmp = node->leaves;

	while (*tmp) {
		p = gr_strdup((*tmp)->filename);
		if (node_len == 1)
			p2 = strchr(p + 1, '/');
		else
			p2 = strchr(p + node_len + 1, '/');

		if (!p2) {
			tmp++;
			cnt++;
			free(p);
			continue;
		}

		*p2 = '\0';
		cachednode = NULL;
		cachedlen = 0;
		insert_file(&node, p, 0, 0);
		free(p);
		cnt++;
		/* node->leaves might have been modified during insert */
		tmp = node->leaves + cnt;
	}

	tmp = node->leaves;

	while (*tmp && num) {
		parent = NULL;
		tmp4 = *tmp;
		tmp2 = tmp;
		while(*(tmp2 + 1)) {
			*tmp2 = *(tmp2 + 1);
			tmp2++;
		}
		*tmp2 = NULL;
		/* cache not needed here */
		cachednode = NULL;
		cachedlen = 0;
		tmp3 = find_insert_file(&node, tmp4, strlen(tmp4->filename), &parent);
		tmp = node->leaves;
		if (!(*tmp3)) {
			*tmp3 = tmp4;
			(*tmp3)->parent = parent;
		}
		num--;
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

		if (object)
			display_tree(object, stream);
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
	struct gr_learn_ip_node **node;

	if (!base)
		return;

	act(base, optarg, contype, stream);
	
	node = base->leaves;

	while(node && *node) {
		traverse_ip_tree(*node, optarg, act, contype, stream);
		node++;
	}

	return;
}

int count_ip_depth(struct gr_learn_ip_node *node)
{
	int depth = 0;

	while ((node = node->parent))
		depth++;

	return depth;
}

unsigned long count_total_ips(struct gr_learn_ip_node *node)
{
	unsigned long ips = 0;
	struct gr_learn_ip_node **tmp;

	tmp = node->leaves;
	if (!tmp)
		return 1;

	while(*tmp) {
		ips += count_total_ips(*tmp);
		tmp++;
	}

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
		
unsigned long count_ips(struct gr_learn_ip_node **ips)
{
	unsigned long ret = 0;

	if (!ips)
		return ret;

	while (*ips) {
		ips++;
		ret++;
	}

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
	struct gr_learn_ip_node **tmpip;
	int i;

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

	if (!node->leaves) {
		return;
	}

	tmpip = node->leaves;

	while(*tmpip) {
		do_reduce_ip_node(*tmpip, actor);
		gr_stat_free(*tmpip);
		*tmpip = NULL;
		tmpip++;
	}

	gr_dyn_free(node->leaves);
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

	switch(depth) {
	case 3:
		return ip_node[3];
	case 2:
		return ip_node[2];
	case 1:
		return ip_node[1];
	case 0:
		return ip_node[0];
	default:
		return 0;
	}

}

struct gr_learn_ip_node ** find_insert_ip(struct gr_learn_ip_node **base, u_int32_t ip,
					  struct gr_learn_ip_node **parent)
{
	struct gr_learn_ip_node *** node = NULL;
	struct gr_learn_ip_node **tmpip = NULL;
	int depth = 0;
	unsigned long num_ips = 0;
	int match = 0;

	if (!(*base)) {
		(*base) = (struct gr_learn_ip_node *)gr_stat_alloc(sizeof(struct gr_learn_ip_node));
		(*base)->root_node = 1;
	}

	depth = count_ip_depth(*base);
	node = &((*base)->leaves);

	tmpip = *node;
	while (tmpip && *tmpip) {
		if ((*tmpip)->ip_node == extract_ip_field(ip, depth)) {
			match = 1;
			break;
		}
		tmpip++;
	}

	if (match && depth < 3) {
		return find_insert_ip(tmpip, ip, parent);
	} else if (match)
		return tmpip;
	else {
		num_ips = count_ips(*node);
		(*node) = (struct gr_learn_ip_node **)gr_dyn_realloc((*node), (2 + num_ips) * sizeof(struct gr_learn_ip_node *));
		memset((*node) + num_ips, 0, 2 * sizeof(struct gr_learn_ip_node *));

		if (depth == 3) {
			*parent = *base;
			return ((*node) + num_ips);
		} else {
			(*((*node) + num_ips)) = (struct gr_learn_ip_node *)gr_stat_alloc(sizeof(struct gr_learn_ip_node));
			(*((*node) + num_ips))->ip_node = extract_ip_field(ip, depth);
			(*((*node) + num_ips))->parent = *base;
			return find_insert_ip(((*node) + num_ips), ip, parent);
		}
	}
}


void insert_ip(struct gr_learn_ip_node **base, u_int32_t ip, u_int16_t port, u_int8_t proto,
		u_int8_t socktype)
{
	struct gr_learn_ip_node **node;
	struct gr_learn_ip_node *parent = NULL;
	struct gr_learn_ip_node *insert;
	u_int8_t ip_node[4];

	insert = (struct gr_learn_ip_node *)gr_stat_alloc(sizeof(struct gr_learn_ip_node));

	insert_port(insert, port);
	insert->ip_proto[proto / 32] = (1 << (proto % 32));
	insert->ip_type |= (1 << socktype);
	memcpy(&ip_node, &ip, sizeof(ip));
	insert->ip_node = ip_node[3];

	node = find_insert_ip(base, ip, &parent);

	if (*node) {
		(*node)->ip_proto[proto / 32] |= (1 << (proto % 32));
		(*node)->ip_type |= (1 << socktype);
		insert_port(*node, port);
		gr_stat_free(*(insert->ports));
		gr_dyn_free(insert->ports);
		gr_stat_free(insert);
		return;
	} else {
		*node = insert;
		(*node)->parent = parent;
	}

	return;
}

static int strcompare(const void *x, const void *y)
{
        struct gr_learn_file_tmp_node *x1 = *(struct gr_learn_file_tmp_node **) x;
        struct gr_learn_file_tmp_node *y1 = *(struct gr_learn_file_tmp_node **) y;

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
insert_learn_role(struct gr_learn_role_entry ***role_list, char *rolename, u_int16_t rolemode)
{
	unsigned long num = 0;
	struct gr_learn_role_entry **tmp;

	if ((*role_list) == NULL)
		*role_list = (struct gr_learn_role_entry **)gr_dyn_alloc(2 * sizeof(struct gr_learn_role_entry *));

	tmp = *role_list;
	while(*tmp) {
		if (!strcmp((*tmp)->rolename, rolename)) {
			(*tmp)->rolemode |= rolemode;
			return *tmp;
		}
		num++;
		tmp++;
	}
	*role_list = (struct gr_learn_role_entry **)gr_dyn_realloc(*role_list, (2 + num) * sizeof(struct gr_learn_role_entry *));
	memset(*role_list + num, 0, 2 * sizeof(struct gr_learn_role_entry *));

	(*((*role_list) + num)) = (struct gr_learn_role_entry *)gr_stat_alloc(sizeof(struct gr_learn_role_entry));
	(*((*role_list) + num))->rolename = gr_strdup(rolename);
	(*((*role_list) + num))->rolemode = rolemode;

	/* give every learned role a / subject */
	insert_learn_role_subject(*((*role_list) + num), conv_filename_to_struct("/", GR_PROCFIND | GR_OVERRIDE));

	return (*((*role_list) + num));
}

struct gr_learn_role_entry *
find_learn_role(struct gr_learn_role_entry **role_list, char *rolename)
{
	struct gr_learn_role_entry **tmp;

	tmp = role_list;
	while(tmp && *tmp) {
		if (!strcmp((*tmp)->rolename, rolename))
			return *tmp;
		tmp++;
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
