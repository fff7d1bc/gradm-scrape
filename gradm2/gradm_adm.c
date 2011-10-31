#include "gradm.h"

int
is_valid_elf_binary(const char *filename)
{
	Elf32_Ehdr header_elf;
	Elf64_Ehdr header_elf64;
	int fd;

	if ((fd = open(filename, O_RDONLY)) < 0)
		return 0;

	if ((read(fd, &header_elf64, sizeof (header_elf64)) != sizeof (header_elf64)))
		goto failure;

	memcpy(&header_elf, &header_elf64, sizeof(header_elf));

	/* binary is 32bit */
	if (header_elf.e_ident[EI_CLASS] == 1) {
		if (strncmp((char *)header_elf.e_ident, ELFMAG, SELFMAG))
			goto failure;

		if (header_elf.e_type != ET_EXEC && header_elf.e_type != ET_DYN)
			goto failure;
	/* binary is 64bit */
	} else if (header_elf64.e_ident[EI_CLASS] == 2) {
		if (strncmp((char *)header_elf64.e_ident, ELFMAG, SELFMAG))
			goto failure;

		if (header_elf64.e_type != ET_EXEC && header_elf64.e_type != ET_DYN)
			goto failure;

	} else
		goto failure;

	close(fd);
	return 1;
      failure:
	close(fd);
	return 0;
}

static void
find_gradm_path(char *gradm_realpath)
{
	char gradm_procpath[21] = { 0 };

	snprintf(gradm_procpath, sizeof (gradm_procpath),
		 "/proc/%d/exe", getpid());

	if (readlink(gradm_procpath, gradm_realpath, PATH_MAX - 1) < 0)
		failure("readlink");

	return;
}

extern int gr_enable;

void
add_gradm_acl(struct role_acl *role)
{
	struct stat fstat;
	char gradm_realpath[PATH_MAX] = { 0 };
	char *gradm_name;
	struct ip_acl ip;
	struct protoent *proto;

	find_gradm_path(gradm_realpath);

	gradm_name = gr_strdup(gradm_realpath);
	if (gr_enable && strcmp(gradm_name, GRADM_PATH)) {
		printf("You are attempting to use a gradm binary other "
		       "than the installed version.  Depending on your "
		       "policy, you could be locking yourself out of "
		       "your machine by enabling the RBAC system with "
		       "this binary.  Press \'y\' if you wish to ignore "
		       "this warning, or any other key to cancel.\n>");
		if (getchar() != 'y')
			exit(EXIT_FAILURE);
	}

	add_proc_subject_acl(role, gradm_name, proc_subject_mode_conv("ado"), 0);

	if (!stat(GRDEV_PATH, &fstat)) {
		add_proc_object_acl(current_subject, GRDEV_PATH, proc_object_mode_conv("w"), GR_FEXIST);
	} else {
		fprintf(stderr, "%s does not "
			"exist.  Please recompile your kernel with "
			"grsecurity and install a newer version of gradm.\n",
			GRDEV_PATH);
		exit(EXIT_FAILURE);
	}

	proto = getprotobyname("udp");
	if (proto == NULL) {
		fprintf(stderr, "Error while parsing /etc/protocols.\n");
		exit(EXIT_FAILURE);
	}
	memset(&ip, 0, sizeof (ip));
	ip.low = 2049;
	ip.high = 2049;
	ip.type = (1 << SOCK_DGRAM);
	ip.proto[proto->p_proto / 32] |= (1 << (proto->p_proto % 32));
	add_ip_acl(current_subject, GR_IP_CONNECT, &ip);
	memset(&ip, 0, sizeof (ip));
	add_ip_acl(current_subject, GR_IP_BIND, &ip);

	add_proc_object_acl(current_subject, "/", proc_object_mode_conv("h"), GR_FEXIST);
	add_proc_object_acl(current_subject, "/etc/ld.so.cache", proc_object_mode_conv("r"), GR_FEXIST);
	add_proc_object_acl(current_subject, "/etc/ld.so.preload", proc_object_mode_conv("r"), GR_FEXIST);
	add_proc_object_acl(current_subject, "/etc/protocols", proc_object_mode_conv("r"), GR_FEXIST);
	add_proc_object_acl(current_subject, "/dev/urandom", proc_object_mode_conv("r"), GR_FEXIST);
	add_proc_object_acl(current_subject, "/lib", proc_object_mode_conv("rx"), GR_FEXIST);
	add_proc_object_acl(current_subject, "/usr/lib", proc_object_mode_conv("rx"), GR_FEXIST);
	/* we add GR_SYMLINK to ignore fatal duplicate errors if /lib64 
	   is symlinked to /lib for whatever reason */
	add_proc_object_acl(current_subject, "/lib64", proc_object_mode_conv("rx"), GR_FEXIST | GR_SYMLINK);
	add_proc_object_acl(current_subject, "/usr/lib64", proc_object_mode_conv("rx"), GR_FEXIST | GR_SYMLINK);
	add_proc_object_acl(current_subject, gradm_name, proc_object_mode_conv("x"), GR_FEXIST);
	add_proc_object_acl(current_subject, GRPAM_PATH, proc_object_mode_conv("x"), GR_FEXIST);

	add_cap_acl(current_subject, "-CAP_ALL", NULL);
	add_cap_acl(current_subject, "+CAP_IPC_LOCK", NULL);

	return;
}

void
add_gradm_pam_acl(struct role_acl *role)
{
	struct ip_acl ip;
	struct protoent *proto;

	add_proc_subject_acl(role, GRPAM_PATH, proc_subject_mode_conv("ado"), 0);

	add_proc_object_acl(current_subject, GRDEV_PATH, proc_object_mode_conv("w"), GR_FEXIST);

	proto = getprotobyname("udp");
	if (proto == NULL) {
		fprintf(stderr, "Error while parsing /etc/protocols.\n");
		exit(EXIT_FAILURE);
	}
	memset(&ip, 0, sizeof (ip));
	ip.low = 2049;
	ip.high = 2049;
	ip.type = (1 << SOCK_DGRAM);
	ip.proto[proto->p_proto / 32] |= (1 << (proto->p_proto % 32));
	add_ip_acl(current_subject, GR_IP_CONNECT, &ip);
	memset(&ip, 0, sizeof (ip));
	add_ip_acl(current_subject, GR_IP_BIND, &ip);

	add_proc_object_acl(current_subject, "/", proc_object_mode_conv("h"), GR_FEXIST);
	add_proc_object_acl(current_subject, "/etc/ld.so.cache", proc_object_mode_conv("r"), GR_FEXIST);
	add_proc_object_acl(current_subject, "/etc/ld.so.preload", proc_object_mode_conv("r"), GR_FEXIST);
	add_proc_object_acl(current_subject, "/etc/localtime", proc_object_mode_conv("r"), GR_FEXIST);
	add_proc_object_acl(current_subject, "/etc/protocols", proc_object_mode_conv("r"), GR_FEXIST);
	add_proc_object_acl(current_subject, "/etc/passwd", proc_object_mode_conv("r"), GR_FEXIST);
	add_proc_object_acl(current_subject, "/etc/shadow", proc_object_mode_conv("r"), GR_FEXIST);
	add_proc_object_acl(current_subject, "/etc/pam.d", proc_object_mode_conv("r"), GR_FEXIST);
	add_proc_object_acl(current_subject, "/etc/pam.conf", proc_object_mode_conv("r"), GR_FEXIST);
	add_proc_object_acl(current_subject, "/etc/security", proc_object_mode_conv("r"), GR_FEXIST);
	add_proc_object_acl(current_subject, "/usr/share/zoneinfo", proc_object_mode_conv("r"), GR_FEXIST);
	add_proc_object_acl(current_subject, "/etc/nsswitch.conf", proc_object_mode_conv("r"), GR_FEXIST);
	add_proc_object_acl(current_subject, "/dev/urandom", proc_object_mode_conv("r"), GR_FEXIST);
	add_proc_object_acl(current_subject, "/proc", proc_object_mode_conv(""), GR_FEXIST);
	add_proc_object_acl(current_subject, "/proc/filesystems", proc_object_mode_conv("r"), GR_FEXIST);
	add_proc_object_acl(current_subject, "/selinux", proc_object_mode_conv("r"), GR_FEXIST);
	add_proc_object_acl(current_subject, "/dev", proc_object_mode_conv(""), GR_FEXIST);
	add_proc_object_acl(current_subject, "/dev/tty", proc_object_mode_conv("rw"), GR_FEXIST);
	add_proc_object_acl(current_subject, "/dev/tty?", proc_object_mode_conv("rw"), GR_FEXIST);
	add_proc_object_acl(current_subject, "/dev/pts", proc_object_mode_conv("rw"), GR_FEXIST);
	add_proc_object_acl(current_subject, "/var/run", proc_object_mode_conv(""), GR_FEXIST);
	add_proc_object_acl(current_subject, "/var/run/utmp", proc_object_mode_conv("rw"), GR_FEXIST);
	add_proc_object_acl(current_subject, "/var/run/utmpx", proc_object_mode_conv("rw"), GR_FEXIST);
	add_proc_object_acl(current_subject, "/var/log/faillog", proc_object_mode_conv("rw"), GR_FEXIST);
	add_proc_object_acl(current_subject, "/dev/log", proc_object_mode_conv("rw"), GR_FEXIST);
	add_proc_object_acl(current_subject, "/dev/null", proc_object_mode_conv("rw"), GR_FEXIST);
	add_proc_object_acl(current_subject, "/lib", proc_object_mode_conv("rx"), GR_FEXIST);
	add_proc_object_acl(current_subject, "/usr/lib", proc_object_mode_conv("rx"), GR_FEXIST);
	add_proc_object_acl(current_subject, "/lib64", proc_object_mode_conv("rx"), GR_FEXIST | GR_SYMLINK);
	add_proc_object_acl(current_subject, "/usr/lib64", proc_object_mode_conv("rx"), GR_FEXIST | GR_SYMLINK);
	add_proc_object_acl(current_subject, GRPAM_PATH, proc_object_mode_conv("x"), GR_FEXIST);

	add_cap_acl(current_subject, "-CAP_ALL", NULL);
	add_cap_acl(current_subject, "+CAP_IPC_LOCK", NULL);
	add_cap_acl(current_subject, "+CAP_AUDIT_WRITE", NULL);

	return;
}

void
add_kernel_acl(void)
{
	add_role_acl(&current_role, gr_strdup(":::kernel:::"), role_mode_conv("sN"), 1);

	add_proc_subject_acl(current_role, "/", proc_subject_mode_conv("kvo"), 0);

	add_proc_object_acl(current_subject, "/", proc_object_mode_conv("rwxcdl"), GR_FEXIST);
	add_proc_object_acl(current_subject, GRSEC_DIR, proc_object_mode_conv("h"), GR_FEXIST);

	return;
}

void
add_grlearn_acl(struct role_acl *role)
{
	struct stat fstat;
	struct ip_acl ip;

	if (stat(GRLEARN_PATH, &fstat)) {
		fprintf(stderr, "%s does not exist.  Please reinstall gradm.\n", GRLEARN_PATH);
		exit(EXIT_FAILURE);
	}

	add_proc_subject_acl(role, GRLEARN_PATH, proc_subject_mode_conv("hpado"), 0);

	memset(&ip, 0, sizeof (ip));
	add_ip_acl(current_subject, GR_IP_CONNECT, &ip);
	add_ip_acl(current_subject, GR_IP_BIND, &ip);

	add_proc_object_acl(current_subject, "/", proc_object_mode_conv("h"), GR_FEXIST);
	add_proc_object_acl(current_subject, GRLEARN_PATH, proc_object_mode_conv("x"), GR_FEXIST);

	add_cap_acl(current_subject, "-CAP_ALL", NULL);

	return;
}

static void add_fulllearn_admin_acl(void)
{
	add_role_acl(&current_role, gr_strdup("admin"), role_mode_conv("sA"), 0);
	add_proc_subject_acl(current_role, "/", proc_subject_mode_conv("aorvk"), 0);
	add_proc_object_acl(current_subject, "/", proc_object_mode_conv("rwcdmlxi"), GR_FEXIST);

	return;
}

void add_fulllearn_acl(void)
{
	struct ip_acl ip;

	add_kernel_acl();
	add_fulllearn_admin_acl();

	add_role_acl(&current_role, gr_strdup("default"), role_mode_conv("A"), 0);
	add_role_transition(current_role, "admin");
	add_proc_subject_acl(current_role, "/", proc_subject_mode_conv("ol"), 0);

	add_proc_object_acl(current_subject, "/", proc_object_mode_conv("h"), GR_FEXIST);

	add_cap_acl(current_subject, "-CAP_ALL", NULL);

	memset(&ip, 0, sizeof (ip));
	add_ip_acl(current_subject, GR_IP_CONNECT, &ip);
	add_ip_acl(current_subject, GR_IP_BIND, &ip);

	add_gradm_acl(current_role);

	parse_learn_config();

	expand_acls();
	return;
}

void add_rolelearn_acl(void)
{
	struct ip_acl ip;

	add_proc_subject_acl(current_role, "/", proc_subject_mode_conv("ol"), 0);

	add_proc_object_acl(current_subject, "/", proc_object_mode_conv("h"), GR_FEXIST);

	add_cap_acl(current_subject, "-CAP_ALL", NULL);

	memset(&ip, 0, sizeof (ip));
	add_ip_acl(current_subject, GR_IP_CONNECT, &ip);
	add_ip_acl(current_subject, GR_IP_BIND, &ip);

	return;
}

void start_grlearn(char *logfile)
{
	pid_t pid;
	int ret;

	unlink(GR_LEARN_PIPE_PATH);
	ret = mkfifo(GR_LEARN_PIPE_PATH, S_IRUSR | S_IWUSR);
	if (ret == -1) {
		fprintf(stderr, "Error creating pipe.\n");
		exit(EXIT_FAILURE);
	}

	pid = fork();

	if (!pid) {
		execl(GRLEARN_PATH, GRLEARN_PATH, logfile, NULL);
		exit(EXIT_FAILURE);
	} else if (pid > 0) {
		char b;
		int read_bytes;
		int fd;

		fd = open(GR_LEARN_PIPE_PATH, O_RDONLY);
		if (fd < 0) {
			fprintf(stderr, "Unable to open pipe.\n");
			kill(pid, 9);
			exit(EXIT_FAILURE);
		}

		read_bytes = read(fd, &b, 1);
		close(fd);
	} else {
		fprintf(stderr, "Error starting grlearn.\n");
		exit(EXIT_FAILURE);
	}

	return;
}

void stop_grlearn(void)
{
	pid_t pid;

	pid = fork();

	if (!pid) {
		execl(GRLEARN_PATH, GRLEARN_PATH, "-stop", NULL);
	}

	return;
}
