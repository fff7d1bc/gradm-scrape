#ifndef GRADM_H
#define GRADM_H
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <getopt.h>
#include <sched.h>
#include <fcntl.h>
#include <termios.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#include <fnmatch.h>
#include <elf.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <asm/param.h>
#include <asm/ioctls.h>

#define SIZE(x) (sizeof(x) / sizeof(x[0]))

#define failure(x) do { \
	fprintf(stderr, x ": %s\n\n", strerror(errno)); \
	exit(EXIT_FAILURE);\
  	} while(0)

#define for_each_role(x, y) \
	for(x = y; x; x = (x)->prev)

#define for_each_subject(x, y) \
	for(x = (y)->hash->first; x; x = (x)->prev)

#define for_each_include(x) \
	for(x = includes; x; x = (x)->prev)

#define for_each_object(x, y) \
	for(x = (y)->hash->first; x; x = (x)->prev)

#define for_each_allowed_ip(x, y) \
	for(x = y; x; x = (x)->prev)

#define for_each_transition(x, y) \
	for(x = y; x; x = (x)->prev)

#define for_each_globbed(x, y) \
	for(x = (y)->globbed; x; x = (x)->next)


#define MAJOR_26(dev)     ((unsigned int) ((dev)>>20))
#define MINOR_26(dev)     ((unsigned int) ((dev) & ((1U << 20) - 1)))
#define MKDEV_26(ma,mi)   ((mi & 0xff) | (ma << 8) | ((mi & ~0xff) << 12))
#define MAJOR_24(dev)	((dev)>>8)
#define MINOR_24(dev)	((dev) & 0xff)
#define MKDEV_24(ma,mi)	((ma)<<8 | (mi))

#include "gradm_defs.h"
#include "gradm_func.h"

#endif
