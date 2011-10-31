#include "gradm.h"

extern FILE *gradmin;
extern int gradmparse(void);

void
add_id_transition(struct proc_acl *subject, char *idname, int usergroup, int allowdeny)
{
	struct passwd *pwd;
	struct group *grp;
	int i;

	if (usergroup == GR_ID_USER) {
		if ((subject->user_trans_type | allowdeny) == (GR_ID_ALLOW | GR_ID_DENY)) {
			fprintf(stderr, "Error on line %lu of %s.  You cannot use "
				"both user_transition_allow and user_transition_deny.\n"
				"The RBAC system will not be allowed to be enabled until "
				"this error is fixed.\n", lineno, current_acl_file);
			exit(EXIT_FAILURE);
		}
		subject->user_trans_type |= allowdeny;

		/* dupecheck */
		for (i = 0; i < subject->user_trans_num; i++)
			if (*(subject->user_transitions + i) == usergroup)
				return;

		pwd = getpwnam(idname);
		if (!pwd) {
			/* now try it as a uid */
			unsigned long theuid = 0;
			char *endptr;
			theuid = strtoul(idname, &endptr, 10);
			if (*endptr == '\0')
				pwd = getpwuid((int)theuid);
			if (!pwd || theuid > INT_MAX) {
				fprintf(stderr, "User %s on line %lu of %s "
					"does not exist.\nThe RBAC system will "
					"not be allowed to be enabled until "
					"this error is fixed.\n", idname,
					lineno, current_acl_file);
				exit(EXIT_FAILURE);
			}
		}

		/* increment pointer count upon allocation of user transition list */
		if (subject->user_transitions == NULL)
			num_pointers++;

		subject->user_trans_num++;
		subject->user_transitions = gr_dyn_realloc(subject->user_transitions, subject->user_trans_num * sizeof(uid_t));
		*(subject->user_transitions + subject->user_trans_num - 1) = pwd->pw_uid;
	} else if (usergroup == GR_ID_GROUP) {
		if ((subject->group_trans_type | allowdeny) == (GR_ID_ALLOW | GR_ID_DENY)) {
			fprintf(stderr, "Error on line %lu of %s.  You cannot use "
				"both group_transition_allow and group_transition_deny.\n"
				"The RBAC system will not be allowed to be enabled until "
				"this error is fixed.\n", lineno, current_acl_file);
			exit(EXIT_FAILURE);
		}
		subject->group_trans_type |= allowdeny;

		/* dupecheck */
		for (i = 0; i < subject->group_trans_num; i++)
			if (*(subject->group_transitions + i) == usergroup)
				return;

		grp = getgrnam(idname);

		if (!grp) {
			/* now try it as a gid */
			unsigned long thegid = 0;
			char *endptr;
			thegid = strtoul(idname, &endptr, 10);
			if (*endptr == '\0')
				grp = getgrgid((int)thegid);
			if (!grp || thegid > INT_MAX) {
				fprintf(stderr, "Group %s on line %lu of %s "
					"does not exist.\nThe RBAC system will "
					"not be allowed to be enabled until "
					"this error is fixed.\n", idname,
					lineno, current_acl_file);
				exit(EXIT_FAILURE);
			}
		}

		/* increment pointer count upon allocation of group transition list */
		if (subject->group_transitions == NULL)
			num_pointers++;

		subject->group_trans_num++;
		subject->group_transitions = gr_dyn_realloc(subject->group_transitions, subject->group_trans_num * sizeof(gid_t));
		*(subject->group_transitions + subject->group_trans_num - 1) = grp->gr_gid;
	}

	return;
}

static int
is_role_dupe(struct role_acl *role, const char *rolename, const u_int16_t type)
{
	struct role_acl *tmp;

	for_each_role(tmp, role)
	    if ((tmp->roletype & (GR_ROLE_USER | GR_ROLE_GROUP | GR_ROLE_SPECIAL) & type) && !strcmp(tmp->rolename, rolename))
		return 1;

	return 0;
}

void
add_domain_child(struct role_acl *role, char *idname)
{
	struct passwd *pwd;
	struct group *grp;

	if (is_role_dupe(current_role, idname, role->roletype)) {
		fprintf(stderr, "Duplicate role %s on line %lu of %s.\n"
			"The RBAC system will not be allowed to be "
			"enabled until this error is fixed.\n",
			idname, lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	/* reason for this is that in the kernel, the hash table which is keyed by UID/GID
	   has a size dependent on the number of roles.  Since we want to fake a domain
	   as being a real role for each of those users/groups by providing a pointer
	   to the domain for each user/group, we need to count each of these against the
	   role count */
	num_domain_children++;

	/* increment pointer count upon allocation of domain list */
	if (role->domain_children == NULL)
		num_pointers++;

	if (role->roletype & GR_ROLE_USER) {
		pwd = getpwnam(idname);

		if (!pwd) {
			/* now try it as a uid */
			unsigned long theuid = 0;
			char *endptr;
			theuid = strtoul(idname, &endptr, 10);
			if (*endptr == '\0')
				pwd = getpwuid((int)theuid);
			if (!pwd || theuid > INT_MAX) {
				fprintf(stderr, "User %s on line %lu of %s "
					"does not exist.\nThe RBAC system will "
					"not be allowed to be enabled until "
					"this error is fixed.\n", idname,
					lineno, current_acl_file);
				exit(EXIT_FAILURE);
			}
		}

		role->domain_child_num++;
		role->domain_children = gr_dyn_realloc(role->domain_children, role->domain_child_num * sizeof(uid_t));
		*(role->domain_children + role->domain_child_num - 1) = pwd->pw_uid;
	} else if (role->roletype & GR_ROLE_GROUP) {
		grp = getgrnam(idname);

		if (!grp) {
			/* now try it as a gid */
			unsigned long thegid = 0;
			char *endptr;
			thegid = strtoul(idname, &endptr, 10);
			if (*endptr == '\0')
				grp = getgrgid((int)thegid);
			if (!grp || thegid > INT_MAX) {
				fprintf(stderr, "Group %s on line %lu of %s "
					"does not exist.\nThe RBAC system will "
					"not be allowed to be enabled until "
					"this error is fixed.\n", idname,
					lineno, current_acl_file);
				exit(EXIT_FAILURE);
			}
		}

		role->domain_child_num++;
		role->domain_children = gr_dyn_realloc(role->domain_children, role->domain_child_num * sizeof(uid_t));
		*(role->domain_children + role->domain_child_num - 1) = grp->gr_gid;
	} else {
		// should never get here
		fprintf(stderr, "Unhandled exception 1.\n");
		exit(EXIT_FAILURE);
	}

	return;
}

void
add_role_transition(struct role_acl *role, char *rolename)
{
	struct role_transition **roletpp;
	struct role_transition *roletp;

	/* one for transition, one for name */
	num_pointers += 2;

	roletp =
	    (struct role_transition *) calloc(1,
					      sizeof (struct role_transition));
	if (!roletp)
		failure("calloc");

	roletpp = &(role->transitions);

	if (*roletpp)
		(*roletpp)->next = roletp;

	roletp->prev = *roletpp;

	roletp->rolename = rolename;

	*roletpp = roletp;

	return;
}

static struct deleted_file *
is_deleted_file_dupe(const char *filename)
{
	struct deleted_file *tmp;

	tmp = deleted_files;

	do {
		if (!strcmp(filename, tmp->filename))
			return tmp;
	} while ((tmp = tmp->next));

	return NULL;
}

static struct deleted_file *
add_deleted_file(char *filename)
{
	struct deleted_file *dfile;
	struct deleted_file *retfile;
	static ino_t ino = 0x10000000;

	ino++;

	if (!deleted_files) {
		deleted_files = malloc(sizeof (struct deleted_file));
		if (!deleted_files)
			failure("malloc");
		deleted_files->filename = filename;
		deleted_files->ino = ino;
		deleted_files->next = NULL;
	} else {
		retfile = is_deleted_file_dupe(filename);
		if (retfile)
			return retfile;
		dfile = malloc(sizeof (struct deleted_file));
		if (!dfile)
			failure("malloc");
		dfile->filename = filename;
		dfile->ino = ino;
		dfile->next = deleted_files;
		deleted_files = dfile;
	}

	return deleted_files;
}

static struct file_acl *
is_proc_object_dupe(struct proc_acl *subject, struct file_acl *object)
{
	struct file_acl *tmp;

	tmp = lookup_acl_object_by_name(subject, object->filename);
	if (tmp)
		return tmp;
	tmp = lookup_acl_object(subject, object);
	if (tmp)
		return tmp;

	return NULL;
}

static struct proc_acl *
is_proc_subject_dupe(struct role_acl *role, struct proc_acl *subject)
{
	struct proc_acl *tmp;

	tmp = lookup_acl_subject_by_name(role, subject->filename);
	if (tmp)
		return tmp;
	tmp = lookup_acl_subject(role, subject);
	if (tmp)
		return tmp;

	return NULL;
}

int
add_role_acl(struct role_acl **role, char *rolename, u_int16_t type, int ignore)
{
	struct role_acl *rtmp;
	struct passwd *pwd;
	struct group *grp;

	if (current_role && current_role->hash == NULL) {
		fprintf(stderr, "Error on line %lu of %s: "
				"Attempting to add the role \"%s\" when "
				"no subjects have been specified for "
				"the previous role \"%s\".\nThe RBAC "
				"system will not be allowed to be "
				"enabled until this error is fixed.\n", 
			lineno, current_acl_file, rolename, current_role->rolename);
		exit(EXIT_FAILURE);
	}

	num_roles++;

	/* one for role, one for name */
	num_pointers += 2;

	if (!rolename) {
		fprintf(stderr, "Out of memory.\n");
		exit(EXIT_FAILURE);
	}

	if ((rtmp =
	     (struct role_acl *) calloc(1, sizeof (struct role_acl))) == NULL)
		failure("calloc");

	rtmp->roletype = type;
	rtmp->rolename = rolename;

	if (strcmp(rolename, "default") && (type & GR_ROLE_DEFAULT)) {
		fprintf(stderr, "No role type specified for %s on line %lu "
			"of %s.\nThe RBAC system will not be allowed to be "
			"enabled until this error is fixed.\n", rolename,
			lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	if (is_role_dupe(*role, rtmp->rolename, rtmp->roletype)) {
		fprintf(stderr, "Duplicate role %s on line %lu of %s.\n"
			"The RBAC system will not be allowed to be "
			"enabled until this error is fixed.\n",
			rtmp->rolename, lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	if (ignore)
		rtmp->uidgid = special_role_uid++;
	else if (strcmp(rolename, "default") || !(type & GR_ROLE_DEFAULT)) {
		if (type & GR_ROLE_USER) {
			pwd = getpwnam(rolename);

			if (!pwd) {
				/* now try it as a uid */
				unsigned long theuid = 0;
				char *endptr;
				theuid = strtoul(rolename, &endptr, 10);
				if (*endptr == '\0')
					pwd = getpwuid((int)theuid);
				if (!pwd || theuid > INT_MAX) {
					fprintf(stderr, "User %s on line %lu of %s "
						"does not exist.\nThe RBAC system will "
						"not be allowed to be enabled until "
						"this error is fixed.\n", rolename,
						lineno, current_acl_file);
					exit(EXIT_FAILURE);
				}
			}

			rtmp->uidgid = pwd->pw_uid;
		} else if (type & GR_ROLE_GROUP) {
			grp = getgrnam(rolename);

			if (!grp) {
				/* now try it as a gid */
				unsigned long thegid = 0;
				char *endptr;
				thegid = strtoul(rolename, &endptr, 10);
				if (*endptr == '\0')
					grp = getgrgid((int)thegid);
				if (!grp || thegid > INT_MAX) {
					fprintf(stderr, "Group %s on line %lu of %s "
						"does not exist.\nThe RBAC system will "
						"not be allowed to be enabled until "
						"this error is fixed.\n", rolename,
						lineno, current_acl_file);
					exit(EXIT_FAILURE);
				}
			}

			rtmp->uidgid = grp->gr_gid;
		} else if (type & GR_ROLE_SPECIAL) {
			rtmp->uidgid = special_role_uid++;
		}
	}

	if (*role)
		(*role)->next = rtmp;

	rtmp->prev = *role;

	*role = rtmp;

	if (type & GR_ROLE_SPECIAL)
		add_role_transition(*role,rolename);

	if (type & GR_ROLE_AUTH) {
		add_gradm_acl(*role);
		add_gradm_pam_acl(*role);
	}
	if (!(type & GR_ROLE_SPECIAL))
		add_grlearn_acl(*role);
	if (type & GR_ROLE_LEARN)
		add_rolelearn_acl();

	return 1;
}

int count_slashes(char *str)
{
	int i = 0;
	while (*str) {
		if (*str == '/')
			i++;
		str++;
	}

	return i;
}

static int
add_globbing_file(struct proc_acl *subject, char *filename,
		  u_int32_t mode, int type)
{
	char *basepoint = gr_strdup(filename);
	char *p, *p2;
	struct file_acl *anchor;
	struct file_acl *glob, *glob2;
	int lnum, onum;

	/* one for the object itself, one for the filename */
	num_pointers += 2;

	if (!basepoint)
		failure("gr_strdup");

	/* calculate basepoint, eg basepoint of /home/ * /test is /home */
	p = p2 = basepoint;
	while (*p != '\0') {
		if (*p == '/')
			p2 = p;
		if (*p == '?' || *p == '*' || *p == '[')
			break;
		p++;
	}
	/* if base is / */
	if (p2 == basepoint)
		*(p2 + 1) = '\0';
	else
		*p2 = '\0';

	anchor = lookup_acl_object_by_name(subject, basepoint);

	if (!anchor) {
		fprintf(stderr, "Error on line %lu of %s:\n"
			"Object %s needs to be specified before globbed object %s\n",
			lineno, current_acl_file, basepoint, filename);
		exit(EXIT_FAILURE);
	}

	free(basepoint);

	if (anchor->globbed) {
		glob = anchor->globbed;
		glob2 = calloc(1, sizeof(struct file_acl));
		if (!glob2)
			failure("calloc");
		onum = count_slashes(filename);
		lnum = count_slashes(glob->filename);
		if (onum > lnum) {
			glob2->next = glob;
			anchor->globbed = glob2;
			glob2->filename = filename;
			glob2->mode = mode;
			glob->prev = glob2;
			return 1;
		}
		while (glob->next) {
			lnum = count_slashes(glob->next->filename);
			if (onum > lnum) {
				glob2->next = glob->next;
				glob->next = glob2;
				glob2->filename = filename;
				glob2->mode = mode;
				glob2->prev = glob;
				glob->next->prev = glob2;
				return 1;
			}
			glob = glob->next;
		}
		glob2->filename = filename;
		glob2->mode = mode;
		glob2->prev = glob;
		glob->next = glob2;
	} else {
		glob2 = calloc(1, sizeof(struct file_acl));
		if (!glob2)
			failure("calloc");
		glob2->filename = filename;
		glob2->mode = mode;
		anchor->globbed = glob2;
	}

	return 1;
}

static void
display_all_dupes(struct proc_acl *subject, struct file_acl *filp2)
{
	struct file_acl *tmp;
	struct stat64 fstat;
	struct file_acl ftmp;

	for_each_object(tmp, subject) {
	    if (!stat64(tmp->filename, &fstat)) {
		ftmp.inode = fstat.st_ino;
		if (is_24_kernel)
			ftmp.dev = MKDEV_24(MAJOR_24(fstat.st_dev), MINOR_24(fstat.st_dev));
		else
			ftmp.dev = MKDEV_26(MAJOR_26(fstat.st_dev), MINOR_26(fstat.st_dev));
		if (ftmp.inode == filp2->inode && ftmp.dev == filp2->dev)
			fprintf(stderr, "%s (due to symlinking/hardlinking)\n", tmp->filename);
	    } else if (!strcmp(tmp->filename, filp2->filename)) {
		fprintf(stderr, "%s\n", tmp->filename);
	    }
	}
	return;
}

static char *
parse_homedir(char *filename)
{
	struct passwd *pwd;
	unsigned int newlen;
	char *newfilename;

	if (!(current_role->roletype & GR_ROLE_USER) ||
	     (current_role->roletype & GR_ROLE_DOMAIN)) {
		fprintf(stderr, "Error on line %lu of %s.  $HOME "
				"is supported only on user roles.\n",
				lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	pwd = getpwuid(current_role->uidgid);

	if (pwd == NULL) {
		fprintf(stderr, "Error: /etc/passwd was modified during parsing.\n");
		exit(EXIT_FAILURE);
	}

	newlen = strlen(pwd->pw_dir) + strlen(filename) - 5 + 1;
		
	newfilename = calloc(1, newlen);

	if (!newfilename) {
		fprintf(stderr, "Out of memory.\n");
		exit(EXIT_FAILURE);
	}

	strcpy(newfilename, pwd->pw_dir);
	strcat(newfilename, (filename + 5));

	return newfilename;
}

static uid_t symlink_uid;

int
add_proc_object_acl(struct proc_acl *subject, char *filename,
		    u_int32_t mode, int type)
{
	struct file_acl *p;
	struct file_acl *p2;
	struct stat64 fstat;
	struct deleted_file *dfile;
	unsigned int file_len;
	char *str;
	static int link_count = 0;

	if (!subject) {
		fprintf(stderr, "Error on line %lu of %s.  Attempt to "
			"add an object without a subject declaration.\n"
			"The RBAC system will not load until this "
			"error is fixed.\n", lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	if (!filename) {
		fprintf(stderr, "Out of memory.\n");
		exit(EXIT_FAILURE);
	}

	if (!strncmp(filename, "$HOME", 5))
		filename = parse_homedir(filename);
	else if (!strncmp(filename, "/dev/pts/", 9)) {
		fprintf(stderr, "Error on line %lu of %s.  Grsecurity does "
				"not support fine-grained policy on devpts mounts.\n"
				"Please change your more fine-grained object to a /dev/pts "
				"object.  This will in addition produce a better policy that "
				"will not break as unnecessarily.\n"
				"The RBAC system will not load until this "
				"error is fixed.\n", lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	str = filename;
	file_len = 0;
	if (!strncmp(filename, "/SYSV", 5))
		return add_globbing_file(subject, filename, mode, type);
	while (*str) {
		file_len++;
		if (*str == '?' || *str == '*')
			return add_globbing_file(subject, filename, mode, type);
		if (*str == '[') {
			char *str2 = str;
			while (*str2) {
				if (*str2 == ']')	
					return add_globbing_file(subject, filename, mode, type);
				str2++;
			}
		}
		str++;
	}

	file_len++;

	num_objects++;
	/* one for the object, one for the filename, one for the name entry struct, and one for the inodev_entry struct in the kernel*/
	num_pointers += 4;

	if (lstat64(filename, &fstat)) {
		/* don't add object for dangling symlink */
		if (type & GR_SYMLINK) {
			num_objects--;
			num_pointers -= 4;
			return 1;
		}
		dfile = add_deleted_file(filename);
		fstat.st_ino = dfile->ino;
		fstat.st_dev = 0;
		mode |= GR_DELETED;
		link_count = 0;
	} else if (S_ISLNK(fstat.st_mode)) {
		if (link_count > MAX_SYMLINK_DEPTH) {
			fprintf(stderr, "Error: Too many levels of symbolic links when accessing "
					"%s\n", filename);
			exit(EXIT_FAILURE);
		} else {
			char buf[PATH_MAX];
			memset(&buf, 0, sizeof (buf));

			if (!(type & GR_SYMLINK))
				symlink_uid = fstat.st_uid;

			if (!realpath(filename, buf)) {
				fprintf(stderr, "Error determining real path for %s\n", filename);
				exit(EXIT_FAILURE);
			}
			link_count++;
			if(!add_proc_object_acl(subject, gr_strdup(buf), mode, type | GR_IGNOREDUPE | GR_SYMLINK))
				return 0;
		}
	} else if ((type & GR_SYMLINK) && (fstat.st_uid != symlink_uid)) {
		/* don't add symlink target if the owner of the symlink !=
		   the owner of the target
		*/
		link_count = 0;
		num_objects--;
		num_pointers -= 4;
		return 1;
	} else {
		link_count = 0;
	}

	if ((p =
	     (struct file_acl *) calloc(1, sizeof (struct file_acl))) == NULL)
		failure("calloc");

	if ((filename[file_len - 2] == '/') && file_len != 2)
		filename[file_len - 2] = '\0';

	if (file_len > PATH_MAX) {
		fprintf(stderr, "Filename too long on line %lu of file %s.\n",
			lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	p->filename = filename;
	p->mode = mode;
	p->inode = fstat.st_ino;
	if (is_24_kernel)
		p->dev = MKDEV_24(MAJOR_24(fstat.st_dev), MINOR_24(fstat.st_dev));
	else
		p->dev = MKDEV_26(MAJOR_26(fstat.st_dev), MINOR_26(fstat.st_dev));

	if (type & GR_FLEARN) {
		struct file_acl *tmp;

		tmp = lookup_acl_object_by_name(subject, p->filename);
		if (tmp) {
			tmp->mode |= mode;
			return 1;
		}
		tmp = lookup_acl_object(subject, p);
		if (tmp) {
			tmp->mode |= mode;
			return 1;
		}
	} else if ((p2 = is_proc_object_dupe(subject, p))) {
		if (type & GR_IGNOREDUPE)
			return 1;
		fprintf(stderr, "Duplicate object found for \"%s\""
			" in role %s, subject %s, on line %lu of %s.\n"
			"\"%s\" references the same object as the following object(s):\n",
			p->filename, current_role->rolename, 
			subject->filename, lineno, 
			current_acl_file ? current_acl_file : "<builtin_fulllearn_policy>", p->filename);
		display_all_dupes(subject, p);
		fprintf(stderr, "specified on an earlier line.  "
			"The RBAC system will not load until this"
			" error is fixed.\n");
		exit(EXIT_FAILURE);
	}

	insert_acl_object(subject, p);

	return 1;
}

int
add_proc_subject_acl(struct role_acl *role, char *filename, u_int32_t mode, int flag)
{
	struct proc_acl *p;
	struct proc_acl *p2;
	struct deleted_file *dfile;
	struct stat fstat;
	unsigned int file_len;

	num_subjects++;
	/* one for the subject, one for the filename */
	num_pointers += 2;

	if (!role) {
		fprintf(stderr, "Error on line %lu of %s.  Attempt to "
			"add a subject without a role declaration.\n"
			"The RBAC system will not load until this "
			"error is fixed.\n", lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	if (!filename) {
		fprintf(stderr, "Out of memory.\n");
		exit(EXIT_FAILURE);
	}

	if (mode & GR_LEARN && mode & GR_INHERITLEARN) {
		fprintf(stderr, "Error on line %lu of %s.  Subject mode "
			"may not include both learn and inherit-learn.\n"
			"The RBAC system will not load until this "
			"error is fixed.\n", lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	if (!strncmp(filename, "$HOME", 5))
		filename = parse_homedir(filename);

	file_len = strlen(filename) + 1;

	if (stat(filename, &fstat)) {
		dfile = add_deleted_file(filename);
		fstat.st_ino = dfile->ino;
		fstat.st_dev = 0;
		mode |= GR_DELETED;
	}

	if ((p =
	     (struct proc_acl *) calloc(1, sizeof (struct proc_acl))) == NULL)
		failure("calloc");

	if (!strcmp(filename, "/") && !(flag & GR_FFAKE))
		role->root_label = p;

	if ((filename[file_len - 2] == '/') && file_len != 2)
		filename[file_len - 2] = '\0';

	if (file_len > PATH_MAX) {
		fprintf(stderr, "Filename too long on line %lu of file %s.\n",
			lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	p->filename = filename;
	p->mode = mode;

	if (is_24_kernel)
		p->dev = MKDEV_24(MAJOR_24(fstat.st_dev), MINOR_24(fstat.st_dev));
	else
		p->dev = MKDEV_26(MAJOR_26(fstat.st_dev), MINOR_26(fstat.st_dev));
	p->inode = fstat.st_ino;

	if (!(flag & GR_FFAKE) && (p2 = is_proc_subject_dupe(role, p))) {
		fprintf(stderr, "Duplicate subject found for \"%s\""
			" in role %s, on line %lu of %s.\n"
			"\"%s\" references the same object as \"%s\""
			" specified on an earlier line.\n"
			"The RBAC system will not load until this"
			" error is fixed.\n", p->filename, 
			role->rolename, lineno,
			current_acl_file, p->filename, p2->filename);
		exit(EXIT_FAILURE);
	}

	/* don't insert nested subjects into main hash */
	if (!(flag & GR_FFAKE))
		insert_acl_subject(role, p);
	else
		insert_nested_acl_subject(p);

	current_subject = p;

	return 1;
}

u_int16_t
role_mode_conv(const char *mode)
{
	int len = strlen(mode) - 1;
	u_int16_t retmode = GR_ROLE_DEFAULT;

	for (; len >= 0; len--) {
		switch (mode[len]) {
		case 'u':
			retmode &= ~GR_ROLE_DEFAULT;
			retmode |= GR_ROLE_USER;
			break;
		case 'g':
			retmode &= ~GR_ROLE_DEFAULT;
			retmode |= GR_ROLE_GROUP;
			break;
		case 's':
			retmode &= ~GR_ROLE_DEFAULT;
			retmode |= GR_ROLE_SPECIAL;
			break;
		case 'l':
			retmode |= GR_ROLE_LEARN;
			break;
		case 'G':
			retmode |= GR_ROLE_AUTH;
			break;
		case 'N':
			retmode |= GR_ROLE_NOPW;
			break;
		case 'A':
			retmode |= GR_ROLE_GOD;
			break;
		case 'T':
			retmode |= GR_ROLE_TPE;
			break;
		
		case 'P':
			retmode |= GR_ROLE_PAM;
			break;
		default:
			fprintf(stderr, "Invalid role mode "
				"\'%c\' found on line %lu "
				"of %s\n", mode[len], lineno, current_acl_file);
			exit(EXIT_FAILURE);
		}
	}

	if ((retmode & (GR_ROLE_NOPW | GR_ROLE_PAM)) == (GR_ROLE_NOPW | GR_ROLE_PAM)) {
		fprintf(stderr, "Error on line %lu of %s.  The role mode must contain only one of the noauth and pamauth modes.\n", lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	if (retmode & GR_ROLE_SPECIAL &&
	    retmode & (GR_ROLE_USER | GR_ROLE_GROUP)) {
		fprintf(stderr, "Error on line %lu of %s.  The role mode must be either "
				"special, or user/group, not both.\n"
				"The RBAC system will not load until this"
				" error is fixed.\n", lineno, current_acl_file); 
		exit(EXIT_FAILURE);
	}

	if ((retmode & (GR_ROLE_USER | GR_ROLE_GROUP)) && (retmode & GR_ROLE_NOPW)) {
		fprintf(stderr, "Error on line %lu of %s.  The role mode \"N\" can only "
				"be used with a special role.\n"
				"The RBAC system will not load until this"
				" error is fixed.\n", lineno, current_acl_file); 
		exit(EXIT_FAILURE);
	}
	if ((retmode & (GR_ROLE_USER | GR_ROLE_GROUP)) ==
		(GR_ROLE_USER | GR_ROLE_GROUP)) {
		fprintf(stderr, "Error on line %lu of %s.  The role mode cannot be both "
				"user or group, you must choose one.\n"
				"The RBAC system will not load until this"
				" error is fixed.\n", lineno, current_acl_file); 
		exit(EXIT_FAILURE);
	}

	return retmode;
}

u_int32_t
proc_subject_mode_conv(const char *mode)
{
	int i;
	u_int32_t retmode = 0;

	retmode |= GR_PROCFIND;

	for (i = 0; i < strlen(mode); i++) {
		switch (mode[i]) {
		case 'T':
			retmode |= GR_NOTROJAN;
			break;
		case 'K':
			retmode |= GR_KILLPROC;
			break;
		case 'C':
			retmode |= GR_KILLIPPROC;
			break;
		case 'A':
			retmode |= GR_PROTSHM;
			break;
		case 'O':
			retmode |= GR_IGNORE;
			break;
		case 'o':
			retmode |= GR_OVERRIDE;
			break;
		case 't':
			retmode |= GR_POVERRIDE;
			break;
		case 'l':
			retmode |= GR_LEARN;
			break;
		case 'h':
			retmode &= ~GR_PROCFIND;
			break;
		case 'p':
			retmode |= GR_PROTECTED;
			break;
		case 'k':
			retmode |= GR_KILL;
			break;
		case 'v':
			retmode |= GR_VIEW;
			break;
		case 'd':
			retmode |= GR_PROTPROCFD;
			break;
		case 'b':
			retmode |= GR_PROCACCT;
			break;
		case 'r':
			retmode |= GR_RELAXPTRACE;
			break;
		case 'i':
			retmode |= GR_INHERITLEARN;
			break;
		case 'a':
			retmode |= GR_KERNELAUTH;
			break;
		default:
			fprintf(stderr, "Invalid subject mode "
				"\'%c\' found on line %lu "
				"of %s\n", mode[i], lineno, current_acl_file);
			exit(EXIT_FAILURE);
		}
	}

	return retmode;
}

u_int32_t
proc_object_mode_conv(const char *mode)
{
	int i;
	u_int32_t retmode = 0;

	retmode |= GR_FIND;

	for (i = 0; i < strlen(mode); i++) {
		switch (mode[i]) {
		case 'r':
			retmode |= GR_READ;
			break;
		case 'w':
			retmode |= GR_WRITE;
			retmode |= GR_APPEND;
			break;
		case 'c':
			retmode |= GR_CREATE;
			break;
		case 'd':
			retmode |= GR_DELETE;
			break;
		case 'x':
			retmode |= GR_EXEC;
			break;
		case 'a':
			retmode |= GR_APPEND;
			break;
		case 'h':
			retmode &= ~GR_FIND;
			break;
		case 'i':
			retmode |= GR_INHERIT;
			break;
		case 't':
			retmode |= GR_PTRACERD;
			break;
		case 'l':
			retmode |= GR_LINK;
			break;
		case 'F':
			retmode |= GR_AUDIT_FIND;
			break;
		case 'R':
			retmode |= GR_AUDIT_READ;
			break;
		case 'W':
			retmode |= GR_AUDIT_WRITE;
			retmode |= GR_AUDIT_APPEND;
			break;
		case 'X':
			retmode |= GR_AUDIT_EXEC;
			break;
		case 'A':
			retmode |= GR_AUDIT_APPEND;
			break;
		case 'I':
			retmode |= GR_AUDIT_INHERIT;
			break;
		case 'M':
			retmode |= GR_AUDIT_SETID;
			break;
		case 'C':
			retmode |= GR_AUDIT_CREATE;
			break;
		case 'D':
			retmode |= GR_AUDIT_DELETE;
			break;
		case 'L':
			retmode |= GR_AUDIT_LINK;
			break;
		case 's':
			retmode |= GR_SUPPRESS;
			break;
		case 'm':
			retmode |= GR_SETID;
			break;
		case 'p':
			retmode |= GR_NOPTRACE;
			break;
		default:
			fprintf(stderr, "Invalid proc object mode "
				"\'%c\' found on line %lu "
				"of %s\n", mode[i], lineno, current_acl_file);
		}
	}

	return retmode;
}

void
parse_acls(void)
{
	if (chdir(GRSEC_DIR) < 0) {
		fprintf(stderr, "Error changing directory to %s\n"
			"Error: %s\n", GRSEC_DIR, strerror(errno));
		exit(EXIT_FAILURE);
	}

	gradmin = open_acl_file(GR_POLICY_PATH);
	change_current_acl_file(GR_POLICY_PATH);
	gradmparse();

	add_kernel_acl();

	return;
}

static void
setup_special_roles(struct gr_arg *grarg)
{
	struct role_acl *rtmp = NULL;
	struct gr_pw_entry entry;
	int err;
	u_int16_t i = 0;

	memset(&entry, 0, sizeof (struct gr_pw_entry));

	err = mlock(&entry, sizeof (struct gr_pw_entry));
	if (err && !getuid())
		fprintf(stderr, "Warning, unable to lock authentication "
			"structure in physical memory.\n");

	for_each_role(rtmp, current_role) {
		if (rtmp->roletype & GR_ROLE_SPECIAL &&
		    !(rtmp->roletype & (GR_ROLE_NOPW | GR_ROLE_PAM))) {
			strncpy((char *)entry.rolename, rtmp->rolename, GR_SPROLE_LEN);
			entry.rolename[GR_SPROLE_LEN - 1] = '\0';
			if (!read_saltandpass
			    (entry.rolename, entry.salt, entry.sum)) {
				fprintf(stderr,
					"No password exists for special "
					"role %s.\nRun gradm -P %s to set up a password "
					"for the role.\n", rtmp->rolename,
					rtmp->rolename);
				exit(EXIT_FAILURE);
			}
			grarg->sprole_pws[i].rolename =
			    (unsigned char *) rtmp->rolename;
			memcpy(grarg->sprole_pws[i].salt, entry.salt,
			       GR_SALT_SIZE);
			memcpy(grarg->sprole_pws[i].sum, entry.sum,
			       GR_SHA_SUM_SIZE);
			memset(&entry, 0, sizeof (struct gr_pw_entry));
			i++;
		}
	}

	return;
}

struct gr_arg_wrapper *
conv_user_to_kernel(struct gr_pw_entry *entry)
{
	struct gr_arg_wrapper *wrapper;
	struct gr_arg *retarg;
	struct user_acl_role_db *role_db;
	struct role_acl *rtmp = NULL;
	struct role_acl **r_tmp = NULL;
	unsigned long racls = 0;
	u_int16_t sproles = 0;
	int err;

	for_each_role(rtmp, current_role) {
		racls++;
		if (rtmp->roletype & GR_ROLE_SPECIAL &&
		    !(rtmp->roletype & (GR_ROLE_NOPW | GR_ROLE_PAM)))
			sproles++;
	}

	if ((retarg =
	     (struct gr_arg *) calloc(1, sizeof (struct gr_arg))) == NULL)
		failure("calloc");

	if ((wrapper =
	     (struct gr_arg_wrapper *) calloc(1, sizeof (struct gr_arg_wrapper))) == NULL)
		failure("calloc");

	wrapper->version = GRADM_VERSION;
	wrapper->size = sizeof(struct gr_arg);
	wrapper->arg = retarg;

	err = mlock(retarg, sizeof (struct gr_arg));
	if (err && !getuid())
		fprintf(stderr, "Warning, unable to lock authentication "
			"structure in physical memory.\n");

	if (!racls)	// we are disabling, don't want to calloc 0
		goto set_pw;

	if ((retarg->sprole_pws =
	     (struct sprole_pw *) calloc(sproles,
					 sizeof (struct sprole_pw))) == NULL)
		failure("calloc");

	err = mlock(retarg->sprole_pws, sproles * sizeof (struct sprole_pw));
	if (err && !getuid())
		fprintf(stderr, "Warning, unable to lock authentication "
			"structure in physical memory.\n");

	setup_special_roles(retarg);

	retarg->num_sprole_pws = sproles;

	role_db = (struct user_acl_role_db *) calloc(1, sizeof (struct user_acl_role_db));
	if (role_db == NULL)
		failure("calloc");

	role_db->num_pointers = num_pointers;
	role_db->num_roles = num_roles;
	role_db->num_domain_children = num_domain_children;
	role_db->num_subjects = num_subjects;
	role_db->num_objects = num_objects;

	if ((r_tmp = role_db->r_table =
	     (struct role_acl **) calloc(racls,
					 sizeof (struct role_acl *))) == NULL)
		failure("calloc");

	for_each_role(rtmp, current_role) {
		*r_tmp = rtmp;
		r_tmp++;
	}

	memcpy(&retarg->role_db, role_db, sizeof (struct user_acl_role_db));
      set_pw:

	strncpy((char *)retarg->pw, (char *)entry->passwd, GR_PW_LEN - 1);
	retarg->pw[GR_PW_LEN - 1] = '\0';
	strncpy((char *)retarg->sp_role, (char *)entry->rolename, GR_SPROLE_LEN);
	retarg->sp_role[GR_SPROLE_LEN - 1] = '\0';

	retarg->mode = entry->mode;
	retarg->segv_inode = entry->segv_inode;
	retarg->segv_dev = entry->segv_dev;
	retarg->segv_uid = entry->segv_uid;

	memset(entry, 0, sizeof (struct gr_pw_entry));

	return wrapper;
}
