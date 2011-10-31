#include "gradm.h"

void
write_user_passwd(struct gr_pw_entry *entry)
{
	int fd;
	int len;
	off_t offset;
	unsigned char total[GR_SPROLE_LEN + GR_SHA_SUM_SIZE + GR_SALT_SIZE];

	if ((access(GR_PW_PATH, F_OK)) != 0) {
		if ((fd =
		     open(GR_PW_PATH, O_EXCL | O_CREAT,
			  S_IRUSR | S_IWUSR)) < 0) {
			fprintf(stderr, "Could not open %s\n", GR_PW_PATH);
			failure("open");
		}

		close(fd);
	}

	if ((fd = open(GR_PW_PATH, O_RDWR)) < 0) {
		fprintf(stderr, "Could not open %s\n", GR_PW_PATH);
		failure("open");
	}

	while ((len = read(fd, total, sizeof (total))) == sizeof (total)) {
		if (!memcmp(&total, entry->rolename, GR_SPROLE_LEN)) {
			if ((offset =
			     lseek(fd, -sizeof (total),
				   SEEK_CUR)) == (off_t) - 1)
				failure("lseek");
			break;
		}
	}

	if (write(fd, entry->rolename, GR_SPROLE_LEN) != GR_SPROLE_LEN) {
		fprintf(stderr, "Error writing to %s\n", GR_PW_PATH);
		failure("write");
	}

	if (write(fd, entry->salt, GR_SALT_SIZE) != GR_SALT_SIZE) {
		fprintf(stderr, "Error writing to %s\n", GR_PW_PATH);
		failure("write");
	}

	if (write(fd, entry->sum, GR_SHA_SUM_SIZE) != GR_SHA_SUM_SIZE) {
		fprintf(stderr, "Error writing to %s\n", GR_PW_PATH);
		failure("write");
	}

	close(fd);

	return;
}

void
get_user_passwd(struct gr_pw_entry *entry, int mode)
{
	struct termios term;
	struct gr_pw_entry *old = NULL;
	struct gr_pw_entry new;
	int i, err;

	err = mlock(&new, sizeof (new));
	if (err && !getuid())
		fprintf(stderr, "Warning: Unable to lock password "
			"into physical memory.\n");
      start_pw:
	memset(&new, 0, sizeof (struct gr_pw_entry));

	for (i = 0; i <= mode; i++) {
		if (i == GR_PWANDSUM) {
			old = entry;
			entry = &new;
		}

		printf("%s", (i ? "Re-enter Password: " : "Password: "));
		fflush(stdout);

		tcgetattr(STDIN_FILENO, &term);

		if (term.c_lflag & ECHO) {
			term.c_lflag &= ~ECHO;
			tcsetattr(STDIN_FILENO, TCSANOW, &term);
		}

		if ((read(STDIN_FILENO, entry->passwd, GR_PW_LEN)) < 0) {
			fprintf(stderr,
				"\nError reading password from user.\n");
			term.c_lflag |= ECHO;
			tcsetattr(STDIN_FILENO, TCSANOW, &term);
			failure("read");
		}

		printf("\n");
		fflush(stdout);

		term.c_lflag |= ECHO;
		tcsetattr(STDIN_FILENO, TCSANOW, &term);

		entry->passwd[strlen((char *)entry->passwd) - 1] = '\0';

		if ((strlen((char *)entry->passwd) < 6) && mode == 1) {
			fprintf(stderr,
				"Your password must be at least 6 characters in length.\n");
			goto start_pw;
		}

		if (i == GR_PWANDSUM) {
			if (strcmp((char *)old->passwd, (char *)entry->passwd)) {
				fprintf(stderr, "Passwords do not match.\n");
				exit(EXIT_FAILURE);
			}
			entry = old;
			memset(&new, 0, sizeof (struct gr_pw_entry));
			printf("Password written to %s.\n", GR_PW_PATH);
		}
	}

	return;
}

void
generate_salt(struct gr_pw_entry *entry)
{
	int fd;

	if ((fd = open("/dev/urandom", O_RDONLY)) < 0) {
		fprintf(stderr,	"Unable to open /dev/urandom for reading.\n");
		failure("open");
	}

	if (read(fd, entry->salt, GR_SALT_SIZE) != GR_SALT_SIZE) {
		fprintf(stderr, "Unable to read from /dev/urandom\n");
		failure("read");
	}

	return;
}

int
read_saltandpass(unsigned char *rolename, unsigned char *salt, unsigned char *pass)
{
	int fd;
	int len;
	int found = 0;
	unsigned char cmp[GR_SPROLE_LEN];
	unsigned char total[GR_SPROLE_LEN + GR_SHA_SUM_SIZE + GR_SALT_SIZE];

	memset(&cmp, 0, sizeof (cmp));

	fd = open(GR_PW_PATH, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Error opening: %s\n", GR_PW_PATH);
		perror("open");
		exit(EXIT_FAILURE);
	}

	while ((len = read(fd, total, sizeof (total))) == sizeof (total)) {
		if (!memcmp(&total, rolename, GR_SPROLE_LEN)) {
			found = 1;
			break;
		}
	}

	close(fd);

	if (!found && !memcmp(rolename, &cmp, GR_SPROLE_LEN)) {
		fprintf(stderr, "Your password file is not set up correctly.\n"
			"Run gradm -P to set a password.\n");
		exit(EXIT_FAILURE);
	} else if (!found)
		return 0;

	memcpy(salt, total + GR_SPROLE_LEN, GR_SALT_SIZE);
	memcpy(pass, total + GR_SPROLE_LEN + GR_SALT_SIZE, GR_SHA_SUM_SIZE);

	return 1;
}
