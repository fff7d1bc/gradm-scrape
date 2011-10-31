#include "gradm.h"

extern FILE *grlearn_configin;
extern int grlearn_configparse(void);

void check_pam_auth(unsigned char *rolename)
{
	struct stat fstat;
	int pid;

	if (stat(GRPAM_PATH, &fstat)) {
		fprintf(stderr, "PAM authentication support has been disabled "
			"in this install.  Please reinstall gradm with PAM "
			"authentication support.\n");
		exit(EXIT_FAILURE);
	}

	pid = fork();

	if (pid == 0) {
		execl(GRPAM_PATH, GRPAM_PATH, rolename, NULL);
		exit(EXIT_FAILURE);
	} else if (pid > 0) {
		int status = 0;
		wait(&status);
		if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
			return;
	} else {
		fprintf(stderr, "Error forking.\n");
		exit(EXIT_FAILURE);
	}

	fprintf(stderr, "PAM authentication failed.\n");
	exit(EXIT_FAILURE);

	return;
}

void parse_learn_config(void)
{
	grlearn_configin = fopen(GR_LEARN_CONFIG_PATH, "r");
	if (grlearn_configin == NULL) {
		fprintf(stderr, "Unable to open %s: %s\n", GR_LEARN_CONFIG_PATH, strerror(errno));
		exit(EXIT_FAILURE);
	}
	grlearn_configparse();
	fclose(grlearn_configin);
	return;
}


FILE *
open_acl_file(const char *filename)
{
	FILE *aclfile;

	if ((aclfile = fopen(filename, "r")) == NULL) {
		fprintf(stderr, "Unable to open %s for reading.\n", filename);
		failure("fopen");
	}

	return aclfile;
}

int
transmit_to_kernel(struct gr_arg_wrapper *buf)
{
	int fd;
	int err = 0;

	if ((fd = open(GRDEV_PATH, O_WRONLY)) < 0) {
		fprintf(stderr, "Could not open %s.\n", GRDEV_PATH);
		failure("open");
	}

	if (write(fd, buf, sizeof(struct gr_arg_wrapper)) != sizeof(struct gr_arg_wrapper)) {
		err = 1;
		switch (errno) {
		case EFAULT:
			fprintf(stderr, "Error copying structures to the "
				"kernel.\n");
			break;
		case ENOMEM:
			fprintf(stderr, "Out of memory.\n");
			break;
		case EBUSY:
			fprintf(stderr, "You have attempted to authenticate "
				"while authentication was locked, try "
				"again later.\n");
			break;
		case EAGAIN:
			fprintf(stderr, "Your request was ignored, "
				"please check the kernel logs for more "
				"info.\n");
		case EPERM:
			if (buf->arg->mode != GRADM_UNSPROLE)
				fprintf(stderr, "Invalid password.\n");
			else
				fprintf(stderr, "You are not in a special role.\n");
			break;
		case EINVAL:
		default:
			fprintf(stderr, "You are using incompatible "
				"versions of gradm and grsecurity.\n"
				"Please update both versions to the "
				"ones available on the website.\n"
				"Make sure your gradm has been compiled "
				"for the kernel you are currently running.\n");
		}
	}

	close(fd);
	ioctl(0, TIOCNXCL);
	if (buf->arg->mode != GRADM_DISABLE) {
		memset(buf->arg, 0, sizeof(struct gr_arg));
		if (err)
			exit(EXIT_FAILURE);
	} else {
		memset(buf->arg, 0, sizeof(struct gr_arg));
		if (err)
			exit(EXIT_FAILURE);
		else
			stop_grlearn();
	}

	return err;
}

void check_acl_status(u_int16_t reqmode)
{
	int fd;
	int retval;
	struct gr_arg arg;
	struct gr_arg_wrapper wrapper;

	ioctl(0, TIOCEXCL);

	wrapper.version = GRADM_VERSION;
	wrapper.size = sizeof(struct gr_arg);
	wrapper.arg = &arg;
	arg.mode = GRADM_STATUS;

	if ((fd = open(GRDEV_PATH, O_WRONLY)) < 0) {
		fprintf(stderr, "Could not open %s.\n", GRDEV_PATH);
		failure("open");
	}

	retval = write(fd, &wrapper, sizeof(struct gr_arg_wrapper));
	close(fd);

	switch (reqmode) {
	case GRADM_PASSSET:
		if (retval == 3) {
			printf("The terminal you are using is unsafe for this operation.  Use another terminal.\n");
			ioctl(0, TIOCNXCL);
			exit(EXIT_FAILURE);
		}
		break;
	case GRADM_STATUS:
		ioctl(0, TIOCNXCL);
		if (retval == 1) {
			printf("The RBAC system is currently enabled.\n");
			exit(0);
		} else if (retval == 2) {
			printf("The RBAC system is currently disabled.\n");
			exit(1);
		} else if (retval == 3) {
			printf("The terminal you are using is unsafe.  Use another terminal.\n");
			exit(2);
		}
		break;
	case GRADM_ENABLE:
		ioctl(0, TIOCNXCL);
		if (retval == 1) {
			printf("The operation you requested cannot be performed "
				"because the RBAC system is currently enabled.\n");
			exit(EXIT_FAILURE);
		}
		break;
	case GRADM_RELOAD:
	case GRADM_DISABLE:
	case GRADM_SPROLE:
	case GRADM_UNSPROLE:
	case GRADM_MODSEGV:
		if (retval == 2) {
			printf("The operation you requested cannot be performed "
				"because the RBAC system is currently disabled.\n");
			ioctl(0, TIOCNXCL);
			exit(EXIT_FAILURE);
		} else if (retval == 3 && reqmode != GRADM_UNSPROLE) {
			printf("The terminal you are using is unsafe for this operation.  Use another terminal.\n");
			ioctl(0, TIOCNXCL);
			exit(EXIT_FAILURE);
		}
		break;
	}

	return;
}

void
init_variables(void)
{
	extern struct ip_acl ip;
	lineno = 1;

	current_acl_file = NULL;
	current_role = NULL;
	current_subject = NULL;
	num_roles = 0;
	num_subjects = 0;
	num_objects = 0;
	num_pointers = 0;

	dont_reduce_dirs = NULL;
	always_reduce_dirs = NULL;
	protected_paths = NULL;
	high_reduce_dirs = NULL;
	high_protected_paths = NULL;

	add_to_string_array(&high_protected_paths, GRSEC_DIR);
	add_to_string_array(&high_protected_paths, GRDEV_PATH);

	memset(&ip, 0, sizeof (ip));

	return;
}

void
change_current_acl_file(const char *filename)
{
	char *p;

	if ((p = (char *) calloc(strlen(filename) + 1, sizeof (char))) == NULL)
		failure("calloc");

	strcpy(p, filename);

	current_acl_file = p;

	return;
}

int
parent_dir(const char *filename, char *parent_dirent[])
{
	int i;

	if ((strlen(*parent_dirent) <= 1) || (strlen(filename) <= 1))
		return 0;

	for (i = strlen(*parent_dirent) - 1; i >= 0; i--) {
		if (i)
			(*parent_dirent)[i] = '\0';
		if (filename[i] == '/')
			return 1;
	}

	return 0;
}
