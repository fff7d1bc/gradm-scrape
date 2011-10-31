#include "gradm.h"

static struct role_name_table {
	u_int16_t modeint;
	char modechar;
} role_mode_table[] = {
	{
	GR_ROLE_USER, 'u'}, {
	GR_ROLE_GROUP, 'g'}, {
	GR_ROLE_SPECIAL, 's'}, {
	GR_ROLE_AUTH, 'G'}, {
	GR_ROLE_NOPW, 'N'}, {
	GR_ROLE_GOD, 'A'}, {
	GR_ROLE_TPE, 'T'}, {
	GR_ROLE_PAM, 'P'}
};

static struct mode_name_table {
	u_int32_t modeint;
	char modechar;
} mode_table[] = {
	{
	GR_READ, 'r'}, {
	GR_EXEC, 'x'}, {
	GR_WRITE, 'w'}, {
	GR_APPEND, 'a'}, {
	GR_INHERIT, 'i'}, {
	GR_PTRACERD, 't'}, {
	GR_SETID, 'm'}, {
	GR_CREATE, 'c'}, {
	GR_DELETE, 'd'}, {
	GR_LINK, 'l'}, {
	GR_AUDIT_FIND, 'F'}, {
	GR_AUDIT_READ, 'R'}, {
	GR_AUDIT_WRITE, 'W'}, {
	GR_AUDIT_EXEC, 'X'}, {
	GR_AUDIT_APPEND, 'A'}, {
	GR_AUDIT_INHERIT, 'I'}, {
	GR_AUDIT_SETID, 'M'}, {
	GR_AUDIT_CREATE, 'C'}, {
	GR_AUDIT_DELETE, 'D'}, {
	GR_AUDIT_LINK, 'L'}, {
	GR_SUPPRESS, 's'}, {
	GR_NOPTRACE, 'p'}, {
	GR_FIND, 'h'}
};

static struct subj_mode_name_table {
	u_int32_t modeint;
	char modechar;
} subj_mode_table[] = {
	{
	GR_OVERRIDE, 'o'}, {
	GR_KILL, 'k'}, {
	GR_PROTECTED, 'p'}, {
	GR_VIEW, 'v'}, {
	GR_IGNORE, 'O'}, {
	GR_PROCFIND, 'h'}, {
	GR_PROTSHM, 'A'}, {
	GR_KILLPROC, 'K'}, {
	GR_KILLIPPROC, 'C'}, {
	GR_NOTROJAN, 'T'}, {
	GR_PROTPROCFD, 'd'}, {
	GR_PROCACCT, 'b'}, {
	GR_RELAXPTRACE, 'r'}, {
	GR_INHERITLEARN, 'i'}, {
	GR_POVERRIDE, 't'}, {
	GR_KERNELAUTH, 'a'}
};

void
conv_mode_to_str(u_int32_t mode, char *modestr, unsigned short len)
{
	unsigned short i;
	unsigned short x;

	memset(modestr, 0, len);

	for (x = 0, i = 0;
	     i < len
	     && x < (sizeof (mode_table) / sizeof (struct mode_name_table));
	     x++) {
		if (mode_table[x].modeint == GR_WRITE && (mode & GR_WRITE)) {
			modestr[i] = 'w';
			mode &= ~GR_APPEND;
			i++;
			continue;
		}
		if (mode_table[x].modeint == GR_AUDIT_WRITE
		    && (mode & GR_AUDIT_WRITE)) {
			modestr[i] = 'W';
			mode &= ~GR_AUDIT_APPEND;
			i++;
			continue;
		}
		if (mode_table[x].modeint == GR_FIND && !(mode & GR_FIND)) {
			modestr[i] = 'h';
			i++;
			continue;
		} else if (mode_table[x].modeint == GR_FIND)
			continue;

		if (mode & mode_table[x].modeint) {
			modestr[i] = mode_table[x].modechar;
			i++;
		}
	}

	return;
}

void
conv_subj_mode_to_str(u_int32_t mode, char *modestr, unsigned short len)
{
	unsigned short i;
	unsigned short x;

	memset(modestr, 0, len);

	for (x = 0, i = 0;
	     i < len
	     && x <
	     (sizeof (subj_mode_table) / sizeof (struct subj_mode_name_table));
	     x++) {
		if (subj_mode_table[x].modeint == GR_PROCFIND && !(mode & GR_PROCFIND)) {
			modestr[i] = 'h';
			i++;
			continue;
		} else if (subj_mode_table[x].modeint == GR_PROCFIND)
			continue;

		if (mode & subj_mode_table[x].modeint) {
			modestr[i] = subj_mode_table[x].modechar;
			i++;
		}
	}

	return;
}

void
conv_role_mode_to_str(u_int16_t mode, char *modestr, unsigned short len)
{
	unsigned short i;
	unsigned short x;

	memset(modestr, 0, len);

	for (x = 0, i = 0;
	     i < len
	     && x <
	     (sizeof (role_mode_table) / sizeof (struct role_name_table));
	     x++) {
		if (mode & role_mode_table[x].modeint) {
			modestr[i] = role_mode_table[x].modechar;
			i++;
		}
	}

	return;
}
