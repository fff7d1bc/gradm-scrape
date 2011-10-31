#include "gradm.h"
#include <signal.h>

static struct always_reduce_entry {
	char *str;
	unsigned int len;
} *always_reduce_paths;

#define LEARN_BUFFER_SIZE (512 * 1024)
#define MAX_ENTRY_SIZE 16384
#define NUM_CACHE_ENTRIES 640

static char *writebuf;
static char *writep;
static int fd2 = -1;

extern FILE *grlearn_configin;
extern int grlearn2_configparse(void);

static void parse_learn2_config(void)
{
        grlearn_configin = fopen(GR_LEARN_CONFIG_PATH, "r");
        if (grlearn_configin == NULL) {
                fprintf(stdout, "Unable to open %s: %s\n", GR_LEARN_CONFIG_PATH, strerror(errno));
                exit(EXIT_FAILURE);
        }
        grlearn2_configparse();
	fclose(grlearn_configin);
        return;
}

void add_always_reduce(char *str)
{
        unsigned int size = 0;
        if (always_reduce_paths == NULL)
                always_reduce_paths = calloc(2, sizeof(struct always_reduce_entry));
        if (always_reduce_paths == NULL)
		exit(EXIT_FAILURE);
        while (always_reduce_paths[size].str)
                size++;

	always_reduce_paths = realloc(always_reduce_paths, (size + 2) * sizeof(struct always_reduce_entry));
        if (always_reduce_paths == NULL)
		exit(EXIT_FAILURE);
	memset(always_reduce_paths + size, 0, 2 * sizeof(struct always_reduce_entry));
	always_reduce_paths[size].str = str;
	always_reduce_paths[size].len = strlen(str);

	return;
}

/* handle flushing of buffer when grlearn is stopped */
void term_handler(int sig)
{
	int ignore_ret;

	signal(sig, SIG_IGN);
	if (fd2 >= 0)
		ignore_ret = write(fd2, writebuf, writep - writebuf);
	exit(0);	
}

int stop_daemon(void)
{
	int fd;
	int ignore_ret;
	pid_t learn_pid;

	fd = open(GR_LEARN_PID_PATH, O_RDONLY);

	if (fd < 0)
		exit(EXIT_FAILURE);

	ignore_ret = read(fd, &learn_pid, sizeof(learn_pid));

	/* send SIGTERM, will be handled */
	kill(learn_pid, 15);

	close(fd);

	unlink(GR_LEARN_PID_PATH);

	return 0;
}
		

int write_pid_log(pid_t pid)
{
	struct stat fstat;
	int fd;
	pid_t learn_pid;
	char pathname[PATH_MAX] = {0};
	char procname[64] = {0};
	int ignore_ret;

	if (!stat(GR_LEARN_PID_PATH, &fstat)) {
		fd = open(GR_LEARN_PID_PATH, O_RDONLY);

		if (fd < 0) {
			fprintf(stdout, "Unable to open %s:\n"
				"%s\n", GR_LEARN_PID_PATH, strerror(errno));
			kill(pid, 9);
			exit(EXIT_FAILURE);
		}

		ignore_ret = read(fd, &learn_pid, sizeof(learn_pid));
		close(fd);
		unlink(GR_LEARN_PID_PATH);

		snprintf(procname, sizeof(procname) - 1, "/proc/%d/exe", learn_pid);
		if (readlink(procname, pathname, PATH_MAX - 1) < 0)
			goto start;
		if (strcmp(pathname, GRLEARN_PATH))
			goto start;
		fprintf(stdout, "Learning daemon possibly running already...killing process.\n");

		kill(learn_pid, 15);
	}
start:		
	fd = open(GR_LEARN_PID_PATH, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);

	if (fd < 0) {
		fprintf(stdout, "Unable to open %s:\n"
			"%s\n", GR_LEARN_PID_PATH, strerror(errno));
		kill(pid, 9);
		exit(EXIT_FAILURE);
	}

	ignore_ret = write(fd, &pid, sizeof(pid));

	close(fd);

	return 0;
}

struct cache_entry {
	char *entryname;
	unsigned long used;
	unsigned long checked;
	unsigned int len;
	unsigned char taken;
} *cache[NUM_CACHE_ENTRIES];
static unsigned long check_count = 0;

/* maintain a cache of most recently used items */
int check_cache(char *str, unsigned int len)
{
	int i;
	check_count++;
	for (i = 0; i < NUM_CACHE_ENTRIES; i++) {
		if (cache[i]->taken && cache[i]->len == len &&
		    !strcmp(cache[i]->entryname, str)) {
			cache[i]->used++;
			return 1;
		}
	}

	return 0;
}

void insert_into_cache(char *str, unsigned int len)
{
	int i;
	struct cache_entry *least;
	int start = random() % (NUM_CACHE_ENTRIES - 1);

	least = cache[start];

	for (i = start + 1; i != start; i = (i + 1) % NUM_CACHE_ENTRIES) {
		if (!cache[i]->taken) {
			cache[i]->taken = 1;
			least = cache[i];
			break;
		}
		if (cache[i]->used < least->used && (cache[i]->checked + (NUM_CACHE_ENTRIES * 2)) < check_count)
			least = cache[i];
	}

	strcpy(least->entryname, str);
	least->used = 0;
	least->len = len;
	least->checked = check_count;

	return;
}
		
char * rewrite_learn_entry(char *p)
{
	int i;
	char *tmp = p;
	char *endobj;
	char *next;
	unsigned int len;
	struct always_reduce_entry *arep;

	for (i = 0; i < 8; i++) {
		tmp = strchr(tmp, '\t');
		if (!tmp)
			return p;
		tmp++;
	}
	/* now we have a pointer to the object name */
	endobj = strchr(tmp, '\t');
	if (!endobj)
		return p;
	*endobj = '\0';
	/* now we have separated the string */

	if (!strncmp(tmp, "/proc/", 6) && (*(tmp + 6) >= '1') &&
	    (*(tmp + 6) <= '9')) {
		*endobj = '\t';
		next = endobj;
		while (*next++);
		len = next - endobj;
		memmove(tmp + 5, endobj, len);
		return next;
	}

	if (always_reduce_paths) {
		arep = always_reduce_paths;
		while (arep && arep->str) {
			if (!strncmp(tmp, arep->str, arep->len) &&
			    (*(tmp + arep->len) == '/')) {
				*endobj = '\t';
				next = endobj;
				while (*next++);
				len = next - endobj;
				memmove(tmp + arep->len, endobj, len);
				return next;
			}
			arep++;
		}
	}

	*endobj = '\t';
	return p;
}

int main(int argc, char *argv[])
{
	char *buf;
	char *next;
	char *p;
	ssize_t retval;
	struct pollfd fds;
	int fd;
	pid_t pid;
	struct sched_param schedulerparam;
	unsigned int len;
	int i;
	int ignore_ret;

	if (argc != 2)
		return 1;
	
	if (!strcmp(argv[1], "-stop"))
		return stop_daemon();
		
	signal(SIGTERM, term_handler);

	parse_learn2_config();

	/* perform various operations to make us act in near real-time */

	srandom(getpid());

	mlockall(MCL_CURRENT | MCL_FUTURE);

	buf = calloc(1, LEARN_BUFFER_SIZE);
	if (!buf)
		return 1;
	writebuf = calloc(1, 4 * MAX_ENTRY_SIZE);
	if (!writebuf)
		return 1;
	writep = writebuf;
	for(i = 0; i < NUM_CACHE_ENTRIES; i++) {
		cache[i] = calloc(1, sizeof(struct cache_entry));
		if (!cache[i])
			return 1;
		cache[i]->entryname = calloc(1, MAX_ENTRY_SIZE);
		if (!cache[i]->entryname)
			return 1;
	}

	setpriority(PRIO_PROCESS, 0, -20);
	ignore_ret = nice(-19);
	schedulerparam.sched_priority = sched_get_priority_max(SCHED_FIFO);
	sched_setscheduler(0, SCHED_FIFO, &schedulerparam);

	fd = open(GRDEV_PATH, O_RDONLY);

	if (fd < 0) {
		fprintf(stdout, "Error opening %s:\n"
			"%s\n", GRDEV_PATH, strerror(errno));
		exit(EXIT_FAILURE);
	}

	fd2 = open(argv[1], O_WRONLY | O_APPEND | O_CREAT, S_IRUSR | S_IWUSR);

	if (fd2 < 0) {
		fprintf(stdout, "Error opening %s\n"
			"%s\n", argv[1], strerror(errno));
		exit(EXIT_FAILURE);
	}

	fcntl(fd, F_SETFD, FD_CLOEXEC);
	fcntl(fd2, F_SETFD, FD_CLOEXEC);

	pid = fork();

	if (pid > 0) {
		exit(EXIT_SUCCESS);
	} else if (!pid) {
		char b;
		int pipefd;

		write_pid_log(getpid());
		pipefd = open(GR_LEARN_PIPE_PATH, O_WRONLY);
		if (pipefd >= 0) {
			ignore_ret = write(pipefd, &b, 1);
			close(pipefd);
		}
		close(0);
		close(1);
		close(2);
	} else {
		char b;
		int pipefd;
		pipefd = open(GR_LEARN_PIPE_PATH, O_WRONLY);
		if (pipefd >= 0) {
			ignore_ret = write(pipefd, &b, 1);
			close(pipefd);
		}
		fprintf(stdout, "Unable to fork.\n");
		exit(EXIT_FAILURE);
	}

	fds.fd = fd;
	fds.events = POLLIN;

	while (poll(&fds, 1, -1) > 0) {
		retval = read(fd, buf, LEARN_BUFFER_SIZE);
		if (retval > 0) {
			p = buf;
			while (p < (buf + retval)) {
				next = rewrite_learn_entry(p);
				len = strlen(p);
				if (!check_cache(p, len)) {
					insert_into_cache(p, len);
					if (((4 * MAX_ENTRY_SIZE) - (writep - writebuf)) > len) {
						memcpy(writep, p, len);
						writep += len;
					} else {
						ignore_ret = write(fd2, writebuf, writep - writebuf);
						memset(writebuf, 0, sizeof(4 * MAX_ENTRY_SIZE));
						writep = writebuf;
					}
				}
				if (next == p)
					p += len + 1;
				else
					p = next;
			}
		}
	}

	close(fd);
	close(fd2);

	return 0;
}
