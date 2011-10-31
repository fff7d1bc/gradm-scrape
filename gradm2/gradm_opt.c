#include "gradm.h"

static void
expand_acl(struct proc_acl *proc, struct role_acl *role)
{
	char *tmpproc;
	struct proc_acl *tmpp;

	tmpproc = alloca(strlen(proc->filename) + 1);
	strcpy(tmpproc, proc->filename);

	while (parent_dir(proc->filename, &tmpproc)) {
		tmpp = lookup_acl_subject_by_name(role, tmpproc);
	        if (tmpp) {
			proc->parent_subject = tmpp;
			return;
		}
	}

	return;
}

void
expand_acls(void)
{
	struct proc_acl *proc;
	struct role_acl *role;
	struct stat fstat;

	for_each_role(role, current_role) {
		for_each_subject(proc, role) {
			if (!stat(proc->filename, &fstat) && S_ISREG(fstat.st_mode)) {
				add_proc_object_acl(proc, gr_strdup(proc->filename), proc_object_mode_conv("rx"), GR_FLEARN);
			}
			/* if we're not nested and not /, set parent subject */
			if (!(proc->mode & GR_OVERRIDE) && !(proc->mode & GR_NESTED) && strcmp(proc->filename, "/"))
				expand_acl(proc, role);
		}
	}

	return;
}
