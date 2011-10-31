#include "gradm.h"

#define ADD_OBJ(x, y) \
		add_proc_object_acl(current_subject, (x), proc_object_mode_conv(y), GR_FEXIST)

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
		ADD_OBJ(GRDEV_PATH, "w");
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

	ADD_OBJ("/", "h");
	ADD_OBJ("/etc/ld.so.cache", "r");
	ADD_OBJ("/etc/ld.so.preload", "r");
	ADD_OBJ("/etc/protocols", "r");
	ADD_OBJ("/dev/urandom", "r");
	ADD_OBJ("/lib", "rx");
	ADD_OBJ("/usr/lib", "rx");
	ADD_OBJ("/lib32", "rx");
	ADD_OBJ("/usr/lib32", "rx");
	ADD_OBJ("/lib64", "rx");
	ADD_OBJ("/usr/lib64", "rx");
	ADD_OBJ(gradm_name, "x");
	ADD_OBJ(GRPAM_PATH, "x");

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

	ADD_OBJ(GRDEV_PATH, "w");

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

	ADD_OBJ("/", "h");
	ADD_OBJ("/etc/default/passwd", "r");
	ADD_OBJ("/etc/ld.so.cache", "r");
	ADD_OBJ("/etc/ld.so.preload", "r");
	ADD_OBJ("/etc/localtime", "r");
	ADD_OBJ("/etc/login.defs", "r");
	ADD_OBJ("/etc/protocols", "r");
	ADD_OBJ("/etc/passwd", "r");
	ADD_OBJ("/etc/shadow", "r");
	ADD_OBJ("/etc/pam.d", "r");
	ADD_OBJ("/etc/pam.conf", "r");
	ADD_OBJ("/etc/security", "r");
	ADD_OBJ("/usr/share/zoneinfo", "r");
	ADD_OBJ("/etc/nsswitch.conf", "r");
	ADD_OBJ("/dev/urandom", "r");
	ADD_OBJ("/proc", "");
	ADD_OBJ("/proc/filesystems", "r");
	ADD_OBJ("/selinux", "r");
	ADD_OBJ("/dev", "");
	ADD_OBJ("/dev/tty", "rw");
	ADD_OBJ("/dev/tty?", "rw");
	ADD_OBJ("/dev/pts", "rw");
	ADD_OBJ("/var/run", "");
	ADD_OBJ("/run", "");
	ADD_OBJ("/var/run/utmp", "rw");
	ADD_OBJ("/var/run/utmpx", "rw");
	ADD_OBJ("/var/log/faillog", "rw");
	ADD_OBJ("/dev/log", "rw");
	ADD_OBJ("/dev/null", "rw");
	ADD_OBJ("/lib", "rx");
	ADD_OBJ("/usr/lib", "rx");
	ADD_OBJ("/lib32", "rx");
	ADD_OBJ("/usr/lib32", "rx");
	ADD_OBJ("/lib64", "rx");
	ADD_OBJ("/usr/lib64", "rx");
	ADD_OBJ(GRPAM_PATH, "x");

	add_cap_acl(current_subject, "-CAP_ALL", NULL);
	add_cap_acl(current_subject, "+CAP_IPC_LOCK", NULL);
	add_cap_acl(current_subject, "+CAP_AUDIT_WRITE", NULL);

	add_sock_family(current_subject, "netlink");

	return;
}

void
add_kernel_acl(void)
{
	add_role_acl(&current_role, gr_strdup(":::kernel:::"), role_mode_conv("sN"), 1);

	add_proc_subject_acl(current_role, "/", proc_subject_mode_conv("kvo"), 0);

	ADD_OBJ("/", "rwxcdl");
	ADD_OBJ(GRSEC_DIR, "h");

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

	ADD_OBJ("/", "h");
	ADD_OBJ(GRLEARN_PATH, "x");

	add_cap_acl(current_subject, "-CAP_ALL", NULL);

	return;
}

static void add_fulllearn_admin_acl(void)
{
	add_role_acl(&current_role, gr_strdup("admin"), role_mode_conv("sA"), 0);
	add_proc_subject_acl(current_role, "/", proc_subject_mode_conv("aorvk"), 0);
	ADD_OBJ("/", "rwcdmlxi");

	return;
}

static void add_fulllearn_shutdown_acl(void)
{
	struct ip_acl ip;

	add_role_acl(&current_role, gr_strdup("shutdown"), role_mode_conv("sARG"), 0);
	add_proc_subject_acl(current_role, "/", proc_subject_mode_conv("rvkao"), 0);

	ADD_OBJ("/", "");
	ADD_OBJ("/dev", "");
	ADD_OBJ("/dev/urandom", "r");
	ADD_OBJ("/dev/random", "r");
	ADD_OBJ("/etc", "r");
	ADD_OBJ("/bin", "rx");
	ADD_OBJ("/sbin", "rx");
	ADD_OBJ("/lib", "rx");
	ADD_OBJ("/lib32", "rx");
	ADD_OBJ("/lib64", "rx");
	ADD_OBJ("/usr", "rx");
	ADD_OBJ("/proc", "r");
	ADD_OBJ("/boot", "h");
	ADD_OBJ("/dev/grsec", "h");
	ADD_OBJ("/dev/kmem", "h");
	ADD_OBJ("/dev/mem", "h");
	ADD_OBJ("/dev/port", "h");
	ADD_OBJ("/etc/grsec", "h");
	ADD_OBJ("/proc/kcore", "h");
	ADD_OBJ("/proc/slabinfo", "h");
	ADD_OBJ("/proc/modules", "h");
	ADD_OBJ("/proc/kallsyms", "h");
	ADD_OBJ("/lib/modules", "hs");
	ADD_OBJ("/etc/ssh", "h");
	add_cap_acl(current_subject, "-CAP_ALL", NULL);

	memset(&ip, 0, sizeof (ip));
	add_ip_acl(current_subject, GR_IP_CONNECT, &ip);
	add_ip_acl(current_subject, GR_IP_BIND, &ip);

	return;
}

void add_fulllearn_acl(void)
{
	struct ip_acl ip;

	add_kernel_acl();
	add_fulllearn_admin_acl();
	add_fulllearn_shutdown_acl();

	add_role_acl(&current_role, gr_strdup("default"), role_mode_conv("A"), 0);
	add_role_transition(current_role, "admin");
	add_role_transition(current_role, "shutdown");
	add_proc_subject_acl(current_role, "/", proc_subject_mode_conv("ol"), 0);

	ADD_OBJ("/", "h");

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

	ADD_OBJ("/", "h");

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
