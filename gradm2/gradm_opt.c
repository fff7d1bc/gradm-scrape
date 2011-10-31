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
			/* set up the socket families
			   if proc->ips != NULL, then some connect/bind
			   rules were specified
			   we default to allowing unix/local/ipv4 sockets
			   if any connect/bind rules are specified
			*/
			if (proc->ips != NULL) {
				add_sock_family(proc, "unix");
				add_sock_family(proc, "local");
				add_sock_family(proc, "ipv4");
			} else if (!proc->sock_families[0] &&
				   !proc->sock_families[1]) {
			/* there are no connect/bind rules and no
			   socket_family rules, so we must allow
			   all families
			*/
				add_sock_family(proc, "all");
			}

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
