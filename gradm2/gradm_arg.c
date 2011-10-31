#include "gradm.h"

static void
show_version(void)
{
	printf("gradm v%s\n"
	       "Licensed under the GNU General Public License (GPL) version 2 or higher\n"
	       "Copyright 2002-2009 - Brad Spengler, Open Source Security, Inc.\n", GR_VERSION);
	exit(EXIT_SUCCESS);
}

static void
show_help(void)
{
	printf("gradm %s\n"
	       "grsecurity administration program\n\n"
	       "Usage: gradm [option] ... \n\n"
	       "Examples:\n"
	       "	gradm -P\n"
	       "	gradm -F -L /etc/grsec/learning.logs -O /etc/grsec/policy\n"
	       "Options:\n"
	       "	-E, --enable	Enable the grsecurity RBAC system\n"
	       "	-D, --disable	Disable the grsecurity RBAC system\n"
	       "	-C, --check	Check RBAC policy for errors\n"
	       "	-S, --status	Check status of RBAC system\n"
	       "	-F, --fulllearn Enable full system learning\n"
	       "	-P [rolename], --passwd\n"
	       "			Create password for RBAC administration\n"
	       "			or a special role\n"
	       "	-R, --reload	Reload the RBAC system while in admin mode\n"
	       "	-L <filename>, --learn\n"
	       "			Specify the pathname for learning logs\n"
	       "	-O <filename>, --output\n"
	       "			Specify where to place policies generated from\n"
	       "                        learning mode\n"
	       "	-M <filename|uid>, --modsegv\n"
	       "			Remove a ban on a specific file or UID\n"
	       "	-a <rolename> , --auth\n"
	       "			Authenticates to a special role that requires auth\n"
	       "	-u, --unauth    Remove yourself from your current special role\n"
	       "	-n <rolename> , --noauth\n"
	       "			Transitions to a special role that doesn't\n"
	       "                        require authentication\n"
	       "	-p <rolename> , --pamauth\n"
	       "			Authenticates to a special role through PAM\n"
	       "	-V, --verbose   Display verbose policy statistics when enabling system\n"
	       "	-h, --help	Display this help\n"
	       "	-v, --version	Display version information\n",
	       GR_VERSION);

	exit(EXIT_SUCCESS);
	return;
}

static void
conv_name_to_num(const char *filename, u_int32_t *dev, ino_t * inode)
{
	struct stat fstat;

	if (stat(filename, &fstat) != 0) {
		fprintf(stderr, "Unable to stat %s: %s\n", filename,
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (is_24_kernel != 0) {
		*dev = MKDEV_24(MAJOR_24(fstat.st_dev), MINOR_24(fstat.st_dev));
	} else {
		*dev = MKDEV_26(MAJOR_26(fstat.st_dev), MINOR_26(fstat.st_dev));
	}

	*inode = fstat.st_ino;

	return;
}

static void verbose_stats(void)
{
	struct role_acl *rtmp;
	struct proc_acl *stmp;
	struct file_acl *otmp;
	unsigned int uroles=0, groles=0, saroles=0, snroles=0, aroles=0, troles=0;
	unsigned int ksubjs=0, smsubjs=0, tsubjs=0, nsubjs=0, ussubjs=0;
	unsigned int chsobjs=0, tobjs=0;

	for_each_role(rtmp, current_role) {
		if (strcmp(rtmp->rolename,":::kernel:::") == 0) {
			continue;
		}
		troles++;
		if (rtmp->roletype & GR_ROLE_SPECIAL) {
			if (rtmp->roletype & (GR_ROLE_NOPW | GR_ROLE_PAM)) {
				snroles++;
			} else {
				saroles++;
			}
			if (rtmp->roletype & GR_ROLE_GOD) {
				aroles++;
			}
		} else if (rtmp->roletype & GR_ROLE_USER) {
			uroles++;
		} else if (rtmp->roletype & GR_ROLE_GROUP) {
			groles++;
		} else {
			/* default role */
			;
		}
		
		for_each_subject(stmp, rtmp) {
			tsubjs++;

			if ((stmp->mode & GR_PROTECTED) == 0)
				ksubjs++;
			if ((stmp->mode & GR_PROTSHM) == 0)
				smsubjs++;
			if (stmp->ips == NULL)
				ussubjs++;

			for_each_object(otmp, stmp) {
				tobjs++;
				if (otmp->mode & GR_SETID &&
				    ((rtmp->roletype & GR_ROLE_GOD) == 0))
					chsobjs++;
			}
		}
	}				

	printf("Policy statistics:\n");
	printf("-------------------------------------------------------\n");
	printf("Role summary:\n");
	printf("\t%u user roles\n", uroles);
	printf("\t%u group roles\n", groles);
	printf("\t%u special roles with authentication\n", saroles);
	printf("\t%u special roles without authentication\n", snroles);
	printf("\t%u admin roles\n", aroles);
	printf("\t%u total roles\n\n", troles);
	printf("Subject summary:\n");
	printf("\t%u nested subjects\n", nsubjs);
	printf("\t%u subjects can be killed by outside processes\n", ksubjs);
	printf("\t%u subjects have unprotected shared memory\n", smsubjs);
	printf("\t%u subjects with unrestricted sockets\n", ussubjs);
	printf("\t%u total subjects\n\n", tsubjs);
	printf("Object summary:\n");
	printf("\t%u objects in non-admin roles allow chmod +s\n", chsobjs);
	printf("\t%u total objects\n", tobjs);

	return;
}

static FILE *open_learn_log(char *learn_log)
{
	FILE *learnfile = NULL;

	if (strcmp(learn_log, "-") == 0) {
		learnfile = stdin;
	} else {
		learnfile = fopen(learn_log, "r");
		if (learnfile == NULL) {
			fprintf(stderr, "Unable to open learning log: %s.\n"
				"Error: %s\n", learn_log, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	return learnfile;
}

int gr_learn = 0;
int gr_enable = 0;
int gr_check = 0;

void
parse_args(int argc, char *argv[])
{
	int next_option = 0;
	int err;
	int verbose = 0;
	char *output_log = NULL;
	char *learn_log = NULL;
	int gr_output = 0;
	int gr_fulllearn = 0;
	struct gr_pw_entry entry;
	struct gr_arg_wrapper *grarg;
	char cwd[PATH_MAX];
	const char *const short_opts = "SVECFuDP::RL:O:M:a:p:n:hv";
	const struct option long_opts[] = {
		{"help", 0, NULL, 'h'},
		{"version", 0, NULL, 'v'},
		{"status", 0, NULL, 'S'},
		{"enable", 0, NULL, 'E'},
		{"check", 0, NULL, 'C'},
		{"disable", 0, NULL, 'D'},
		{"passwd", 2, NULL, 'P'},
		{"auth", 1, NULL, 'a'},
		{"noauth", 1, NULL, 'n'},
		{"reload", 0, NULL, 'R'},
		{"modsegv", 1, NULL, 'M'},
		{"verbose", 0, NULL, 'V'},
		{"learn", 1, NULL, 'L'},
		{"fulllearn", 0, NULL, 'F'},
		{"output", 1, NULL, 'O'},
		{"unauth", 0, NULL, 'u'},
		{"pamauth", 1, NULL, 'p'},
		{NULL, 0, NULL, 0}
	};

	if (!getcwd(cwd, PATH_MAX - 1)) {
		fprintf(stderr, "Error getting current directory.\n");
		exit(EXIT_FAILURE);
	}

	err = mlock(&entry, sizeof (entry));
	if (err && !getuid())
		fprintf(stderr, "Warning: Unable to lock password "
			"into physical memory.\n");

	memset(&entry, 0, sizeof (struct gr_pw_entry));

	if (argc < 2)
		show_help();

	while ((next_option =
		getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1) {

		switch (next_option) {
		case 'V':
			verbose = 1;
			break;
		case 'S':
			if (argc > 2)
				show_help();
			check_acl_status(GRADM_STATUS);
			break;
		case 'C':
			if (argc > 3 || gr_enable)
				show_help();
			gr_check = 1;
			parse_acls();
			expand_acls();
			analyze_acls();
			break;
		case 'E':
			if (argc > 5 || gr_check)
				show_help();
			entry.mode = GRADM_ENABLE;
			check_acl_status(entry.mode);
			gr_enable = 1;
			parse_acls();
			expand_acls();
			break;
		case 'F':
			if (argc > 7)
				show_help();
			entry.mode = GRADM_ENABLE;
			gr_fulllearn = 1;
			gr_enable = 1;
			break;
		case 'u':
			if (argc > 2)
				show_help();
			entry.mode = GRADM_UNSPROLE;
			check_acl_status(entry.mode);
			grarg = conv_user_to_kernel(&entry);
			transmit_to_kernel(grarg);
			break;
		case 'R':
			if (argc > 3)
				show_help();
			entry.mode = GRADM_RELOAD;
			check_acl_status(entry.mode);
			get_user_passwd(&entry, GR_PWONLY);
			parse_acls();
			expand_acls();
			analyze_acls();
			grarg = conv_user_to_kernel(&entry);
			read_saltandpass(entry.rolename, grarg->arg->salt,
					 grarg->arg->sum);
			transmit_to_kernel(grarg);
			break;
		case 'M':
			if ((argc != 3) || (optind > argc)
			    || (strlen(optarg) < 1))
				show_help();
			entry.mode = GRADM_MODSEGV;
			check_acl_status(entry.mode);
			get_user_passwd(&entry, GR_PWONLY);

			if (isdigit(optarg[0]))
				entry.segv_uid = atoi(optarg);
			else
				conv_name_to_num(optarg, &entry.segv_dev,
						 &entry.segv_inode);
			grarg = conv_user_to_kernel(&entry);
			transmit_to_kernel(grarg);
			exit(EXIT_SUCCESS);
			break;
		case 'D':
			if (argc > 2)
				show_help();
			entry.mode = GRADM_DISABLE;
			check_acl_status(entry.mode);
			get_user_passwd(&entry, GR_PWONLY);
			grarg = conv_user_to_kernel(&entry);
			transmit_to_kernel(grarg);
			exit(EXIT_SUCCESS);
			break;
		case 'L':
			if (argc > 7 || argc < 3)
				show_help();
			gr_learn = 1;
			if (optarg) {
				char pathbuf[PATH_MAX];
				if ((*optarg == '/') || !strcmp(optarg, "-"))
					learn_log = gr_strdup(optarg);
				else {
					strcpy(pathbuf, cwd);
					if (strlen(optarg) + strlen(pathbuf) + 2 > PATH_MAX) {
						fprintf(stderr, "Unable to open %s for learning logs.\n", optarg);
						exit(EXIT_FAILURE);
					}
					strcat(pathbuf, "/");
					strcat(pathbuf, optarg);
					learn_log = gr_strdup(pathbuf);
				}
			}
			break;
		case 'O':
			if (argc > 6 || argc < 3)
				show_help();
			gr_output = 1;
			if (optarg)
				output_log = gr_strdup(optarg);
			break;
		case 'P':
			if (argc > 3)
				show_help();
			entry.mode = GRADM_PASSSET;
			check_acl_status(entry.mode);
			if (argc == 3) {
				strncpy((char *)entry.rolename, argv[2], GR_SPROLE_LEN);
				entry.rolename[GR_SPROLE_LEN - 1] = '\0';
				printf("Setting up password for role %s\n",
				       entry.rolename);
			} else
				printf("Setting up grsecurity RBAC password\n");
			get_user_passwd(&entry, GR_PWANDSUM);
			generate_salt(&entry);
			generate_hash(&entry);
			write_user_passwd(&entry);
			memset(&entry, 0, sizeof (struct gr_pw_entry));
			exit(EXIT_SUCCESS);
			break;
		case 'a':
			if (argc != 3)
				show_help();
			strncpy((char *)entry.rolename, argv[2], GR_SPROLE_LEN);
			entry.rolename[GR_SPROLE_LEN - 1] = '\0';
			entry.mode = GRADM_SPROLE;
			check_acl_status(entry.mode);
			get_user_passwd(&entry, GR_PWONLY);
			grarg = conv_user_to_kernel(&entry);
			transmit_to_kernel(grarg);
			exit(EXIT_SUCCESS);
			break;
		case 'p':
			if (argc != 3)
				show_help();
			strncpy((char *)entry.rolename, argv[2], GR_SPROLE_LEN);
			entry.rolename[GR_SPROLE_LEN - 1] = '\0';
			entry.mode = GRADM_SPROLEPAM;
			check_pam_auth(entry.rolename);
			check_acl_status(entry.mode);
			grarg = conv_user_to_kernel(&entry);
			transmit_to_kernel(grarg);
			exit(EXIT_SUCCESS);
			break;
		case 'n':
			if (argc != 3)
				show_help();
			strncpy((char *)entry.rolename, argv[2], GR_SPROLE_LEN);
			entry.rolename[GR_SPROLE_LEN - 1] = '\0';
			entry.mode = GRADM_SPROLE;
			check_acl_status(entry.mode);
			grarg = conv_user_to_kernel(&entry);
			transmit_to_kernel(grarg);
			exit(EXIT_SUCCESS);
			break;
		case 'v':
			if (argc > 2)
				show_help();
			show_version();
			break;
		case 'h':
			show_help();
			break;
		default:
			show_help();
			break;
		}
	}

	if (gr_check) {
		if (verbose)
			verbose_stats();
		return;
	}

	if ((gr_output && !gr_learn)) {
		fprintf(stderr, "-L and -O must be used together.\n");
		exit(EXIT_FAILURE);
	}

	if ((gr_fulllearn && !gr_learn)) {
		fprintf(stderr, "-L and -F must be used together.\n");
		exit(EXIT_FAILURE);
	}

	if (gr_fulllearn && gr_learn && gr_output)
		gr_enable = 0;

	if (gr_enable) {
		/* analyze here since we know if learning is being used */
		if (!gr_fulllearn)
			analyze_acls();
		check_acl_status(entry.mode);
		if (verbose)
			verbose_stats();
		if (gr_fulllearn)
			add_fulllearn_acl();
		grarg = conv_user_to_kernel(&entry);
		read_saltandpass(entry.rolename, grarg->arg->salt,
				 grarg->arg->sum);
		if (gr_learn) {
			start_grlearn(learn_log);
			free(learn_log);
		}
		transmit_to_kernel(grarg);
	} else if (gr_learn && gr_output) {
		FILE *stream;
		FILE *learnfile;

		learnfile = open_learn_log(learn_log);

		if (!strcmp(output_log, "stdout"))
			stream = stdout;
		else if (!strcmp(output_log, "stderr"))
			stream = stderr;
		else {
			stream = fopen(output_log, "a");
			if (!stream) {
				fprintf(stderr,
					"Unable to open %s for writing.\n"
					"Error: %s\n", output_log,
					strerror(errno));
				exit(EXIT_FAILURE);
			}
		}


		add_to_string_array(&high_protected_paths, GRSEC_DIR);
		add_to_string_array(&high_protected_paths, GRDEV_PATH);
		parse_learn_config();

		if (gr_fulllearn)
			generate_full_learned_acls(learnfile, stream);
		else
			handle_learn_logs(learnfile, stream);

		free(learn_log);
		free(output_log);
	}
	return;
}
