#include "gradm.h"

/* fix broken glibc installs */
#ifndef NR_OPEN
#define NR_OPEN 1024
#endif

char *rlim_table[] = {
	[RLIMIT_CPU] = "RES_CPU",
	[RLIMIT_FSIZE] = "RES_FSIZE",
	[RLIMIT_DATA] = "RES_DATA",
	[RLIMIT_STACK] = "RES_STACK",
	[RLIMIT_CORE] = "RES_CORE",
	[RLIMIT_RSS] = "RES_RSS",
	[RLIMIT_NPROC] = "RES_NPROC",
	[RLIMIT_NOFILE] = "RES_NOFILE",
	[RLIMIT_MEMLOCK] = "RES_MEMLOCK",
	[RLIMIT_AS] = "RES_AS",
	[RLIMIT_LOCKS] = "RES_LOCKS",
	[RLIMIT_SIGPENDING] = "RES_SIGPENDING",
	[RLIMIT_MSGQUEUE] = "RES_MSGQUEUE",
	[RLIMIT_NICE] = "RES_NICE",
	[RLIMIT_RTPRIO] = "RES_RTPRIO",
	[RLIMIT_RTTIME] = "RES_RTTIME",
	[GR_CRASH_RES] = "RES_CRASH"
};

static unsigned short
name_to_res(const char *name)
{
	int i;

	for (i = 0; i < SIZE(rlim_table); i++) {
		if (!rlim_table[i])
			continue;
		if (!strcmp(rlim_table[i], name))
			return i;
	}

	fprintf(stderr, "Invalid resource name: %s "
		"found on line %lu of %s.\n", name, lineno, current_acl_file);
	exit(EXIT_FAILURE);

	return 0;
}

static unsigned int
res_to_mask(unsigned short res)
{
	return (1 << res);
}

static unsigned long
conv_res(const char *lim)
{
	unsigned long res;
	char *p;
	int i;
	unsigned int len = strlen(lim);

	if (!strcmp("unlimited", lim))
		return ~0UL;

	if (isdigit(lim[len - 1]))
		return atol(lim);

	if ((p = (char *) calloc(len + 1, sizeof (char))) == NULL)
		failure("calloc");

	strcpy(p, lim);

	for (i = 0; i < len - 1; i++) {
		if (!isdigit(lim[i])) {
			fprintf(stderr, "Invalid resource limit: %s "
				"found on line %lu of %s.\n", lim, lineno,
				current_acl_file);
			exit(EXIT_FAILURE);
		}
	}

	p[i] = '\0';
	res = atol(p);
	free(p);

	switch (lim[i]) {
	case 'm':
		res = res * 60;
		break;
	case 'h':
		res = res * 60 * 60;
		break;
	case 'd':
		res = res * 60 * 60 * 24;
		break;
	case 's':
		res = res;
		break;
	case 'K':
		res = res << 10;
		break;
	case 'M':
		res = res << 20;
		break;
	case 'G':
		res = res << 30;
		break;
	default:
		fprintf(stderr, "Invalid resource limit: %s "
			"found on line %lu of %s.\n", lim, lineno,
			current_acl_file);
		exit(EXIT_FAILURE);
	}

	return res;
}

void
modify_res(struct proc_acl *proc, int res, unsigned long cur, unsigned long max)
{
	if ((res < 0) || (res >= SIZE(rlim_table)))
		return;

	if (proc->resmask & res_to_mask(res)) {
		proc->res[res].rlim_cur = cur;
		proc->res[res].rlim_max = max;
	}

	return;
}

void
add_res_acl(struct proc_acl *subject, const char *name,
	    const char *soft, const char *hard)
{
	struct rlimit lim;

	if (!subject) {
		fprintf(stderr, "Error on line %lu of %s.  Attempt to "
			"add a resource without a subject declaration.\n"
			"The RBAC system will not load until this "
			"error is fixed.\n", lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	lim.rlim_cur = conv_res(soft);
	lim.rlim_max = conv_res(hard);

	if (!strcmp(name, "RES_NOFILE") &&
	    (((lim.rlim_cur != ~0UL) && (lim.rlim_cur > NR_OPEN)) ||
	     ((lim.rlim_max != ~0UL) && (lim.rlim_max > NR_OPEN)))) {
		fprintf(stderr, "Limits for RES_NOFILE cannot be larger "
			"than %u.\n", NR_OPEN);
		exit(EXIT_FAILURE);
	}

	subject->resmask |= res_to_mask(name_to_res(name));

	memcpy(&(subject->res[name_to_res(name)]), &lim, sizeof (lim));

	return;
}
