%{
#include "gradm.h"
#include "gradm.tab.h"

unsigned long lineno;
char *gr_line;
unsigned int old_state;
unsigned int old_state2;

int gradmerror(char *s);
int gradmwrap(void);
int is_eof(void);
void add_include(char *includename);

struct include_entry {
	unsigned long lineno;
	YY_BUFFER_STATE buffer;
	FILE *file;
	char *name;
	struct include_entry *dirents;
	struct include_entry *next;
	struct include_entry **stack;
	int sp;
};

static struct include_entry include_stack;
static struct include_entry *main_stack;
%}

IP [0-9]{1,3}"."[0-9]{1,3}"."[0-9]{1,3}"."[0-9]{1,3}

%option nounput

%x ROLE_STATE SUBJECT_STATE IP_STATE RES_STATE COMMENT_STATE ROLETYPE_STATE
%x INCLUDE_STATE IPNETMASK_STATE IPPORT_STATE ROLETRANS_STATE
%x VAR_STATE VAR_OBJ_STATE IDTRANS_STATE DOMAIN_STATE DOMAINTYPE_STATE
%x DOMAINLIST_STATE IPIP_STATE IPONLY_STATE REP_STATE CAP_STATE FAMILY_STATE

%%

<*>"\n"					{
					  lineno++;
					  if (YYSTATE == COMMENT_STATE)
						  BEGIN(old_state2);
					  if (YYSTATE != VAR_STATE && YYSTATE != VAR_OBJ_STATE)
						  BEGIN(INITIAL);
					}
<*>"#"					{
					  if (YYSTATE != COMMENT_STATE)
						  old_state2 = YYSTATE;
					  BEGIN(COMMENT_STATE);
					}
<*>[ \t]+				;
<COMMENT_STATE>.*			;

<ROLETYPE_STATE>[ugslGNATPR]*		{
					  gradmlval.shortnum = role_mode_conv(yytext);
					  return ROLE_TYPE;
					}
<DOMAINTYPE_STATE>([ug][GTl]*)|([GTl]*[ug])	{
					  BEGIN(DOMAINLIST_STATE);
					  gradmlval.string = gr_strdup(yytext);
					  return DOMAIN_TYPE;
					}
<DOMAINLIST_STATE>"\\\n"		;
<ROLE_STATE>[_a-zA-Z0-9.-]{1,64}	{
					  BEGIN(ROLETYPE_STATE);
					  gradmlval.string = gr_strdup(yytext);
					  return ROLE_NAME;
					}
<DOMAIN_STATE>[_a-zA-Z0-9.-]{1,64}	{
					  BEGIN(DOMAINTYPE_STATE);
					  gradmlval.string = gr_strdup(yytext);
					  return ROLE_NAME;
					}
<DOMAINLIST_STATE>[_a-zA-Z0-9.-]{1,64}	{
					  gradmlval.string = gr_strdup(yytext);
					  return ROLE_NAME;
					}
<ROLETRANS_STATE>[_a-zA-Z0-9.-]{1,64}	{
					  gradmlval.string = gr_strdup(yytext);
					  return ROLE_NAME;
					}

<SUBJECT_STATE>":"			{ 
					  return ':';
					}
<SUBJECT_STATE>([/]|$[(])[^ :\t\n]*	{
					  gradmlval.string = process_string_replace(yytext);
					  if (strstr(gradmlval.string, "//") || strstr(gradmlval.string, "/./") || strstr(gradmlval.string, "/../"))
						gradmerror("invalid pathname error");
					  return SUBJ_NAME;
					}
<SUBJECT_STATE>["]([/]|$[(])[^:\n]*["]	{
					  gr_line = yytext;
					  gr_line++;
					  *(gr_line + strlen(gr_line) - 1) = '\0';
					  gradmlval.string = process_string_replace(gr_line);
					  if (strstr(gradmlval.string, "//") || strstr(gradmlval.string, "/./") || strstr(gradmlval.string, "/../"))
						gradmerror("invalid pathname error");
					  return SUBJ_NAME;
					}
<SUBJECT_STATE>$HOME[/]?[^ :\t\n]*	{ 
					  gradmlval.string = process_string_replace(yytext);
					  if (strstr(gradmlval.string, "//") || strstr(gradmlval.string, "/./") || strstr(gradmlval.string, "/../"))
						gradmerror("invalid pathname error");
					  return SUBJ_NAME;
					}
<SUBJECT_STATE>["]$HOME[/]?[^:\n]*["]		{
					  gr_line = yytext;
					  gr_line++;
					  *(gr_line + strlen(gr_line) - 1) = '\0';
					  gradmlval.string = process_string_replace(gr_line);
					  if (strstr(gradmlval.string, "//") || strstr(gradmlval.string, "/./") || strstr(gradmlval.string, "/../"))
						gradmerror("invalid pathname error");
					  return SUBJ_NAME;
					}
<SUBJECT_STATE>[TKCAOtolhpkvdbrias]+	{
					  gradmlval.num = proc_subject_mode_conv(yytext);
					  return SUBJ_MODE;
					}

<RES_STATE>"unlimited"			{
					  gradmlval.string = gr_strdup(yytext);
					  return RES_SOFTHARD;
					}
<RES_STATE>[0-9]+[smhdKMG]?		{
					  gradmlval.string = gr_strdup(yytext);
					  return RES_SOFTHARD;
					}

<IPIP_STATE>"!"				{
					  return NOT;
					}
<IPIP_STATE>[-a-zA-Z0-9_]{1,7}("#"[0-9]{1,3})?	{
					  BEGIN(IP_STATE);
					  gr_line = yytext;
					  gradmlval.string = gr_strdup(gr_line);
					  gr_line = strchr(gradmlval.string, '#');
					  if (gr_line != NULL)
						*gr_line = ':';
					  return INTERFACE;
					}
<IPIP_STATE>"disabled"			{
					  return DISABLED;
					}
<IPIP_STATE>[-0-9a-zA-Z.]*[a-zA-Z][-0-9a-zA-Z.]*		{
					  BEGIN(IP_STATE);
					  gradmlval.string = gr_strdup(yytext);
					  return HOSTNAME;
					}
<IPONLY_STATE>{IP}			{
					  gradmlval.num = get_ip(yytext);
					  return IPADDR;
					}
<IPIP_STATE>{IP}			{
					  BEGIN(IP_STATE);
					  gradmlval.num = get_ip(yytext);
					  return IPADDR;
					}
<IP_STATE>[/]				{
					  BEGIN(IPNETMASK_STATE);
					  return *yytext;
					}
<IP_STATE>[:-]				{
					  BEGIN(IPPORT_STATE);
					  return *yytext;
					}
<IP_STATE>"raw_sock"|"dgram"|"rdm"|"stream"|"any_sock" {
					  gradmlval.string = gr_strdup(yytext);
					  return IPTYPE;
					}
<IP_STATE>[a-z_-]+			{
					  gradmlval.string = gr_strdup(yytext);
					  return IPPROTO;
					}
<FAMILY_STATE>[0-9a-z]+			{
					  gradmlval.string = gr_strdup(yytext);
					  return SOCKFAMILY;
					}

<IPNETMASK_STATE>[0-9]{1,2}		{
					  unsigned int bits = atoi(yytext);
					  BEGIN(IP_STATE);
					  if (!bits)
						gradmlval.num = 0;
					  else
						gradmlval.num = 0xffffffff << (32 - bits);
					  return IPNETMASK;
					}
<IPPORT_STATE>[0-9]{1,5}		{
					  unsigned int portcheck = atoi(yytext);
					  BEGIN(IP_STATE);
					  if (portcheck > 65535)
						gradmerror("invalid port number error");
					  gradmlval.shortnum = portcheck;
					  return IPPORT;
					}
<REP_STATE>[^ "':()\t\n]+		{
					  gradmlval.string = gr_strdup(yytext);
					  return REP_ARG;
					}
<REP_STATE>["][^"\t\n]+["]		{
					  gr_line = yytext;
					  gr_line++;
					  *(gr_line + strlen(gr_line) - 1) = '\0';
					  gradmlval.string = gr_strdup(gr_line);
					  return REP_ARG;
					}
"replace"				{
					  old_state = YYSTATE;
					  BEGIN(REP_STATE);
					  return REPLACE;
					}
"define"				{
					  old_state = YYSTATE;
					  BEGIN(VAR_STATE);
					  return DEFINE;
					}
[$][a-zA-Z0-9_]+			{
					  gr_line = yytext;
					  if (!strcmp(gr_line, "$HOME")) {
						gradmlval.string = gr_strdup(gr_line);
						return OBJ_NAME;
					  } else {
					  	gr_line++;
					  	gradmlval.string = gr_strdup(gr_line);
					  	return VARIABLE;
					  }
					}
<VAR_STATE>[a-zA-Z0-9_]+		{
					  gradmlval.string = gr_strdup(yytext);
					  return DEFINE_NAME;
					}
<VAR_STATE>"{"				{
					  BEGIN(VAR_OBJ_STATE);
					  return '{';
					}
<VAR_OBJ_STATE>"}"			{
					  BEGIN(old_state);
					  return '}';
					}
<VAR_OBJ_STATE>[/][^ \t\n]*		{
					  gradmlval.string = gr_strdup(yytext);
					  if (strstr(gradmlval.string, "//") || strstr(gradmlval.string, "/./") || strstr(gradmlval.string, "/../"))
						gradmerror("invalid pathname error");
					  return OBJ_NAME;
					}
<VAR_OBJ_STATE>["][/].*["]		{
					  gr_line = yytext;
					  gr_line++;
					  *(gr_line + strlen(gr_line) - 1) = '\0';
					  gradmlval.string = gr_strdup(gr_line);
					  if (strstr(gradmlval.string, "//") || strstr(gradmlval.string, "/./") || strstr(gradmlval.string, "/../"))
						gradmerror("invalid pathname error");
					  return OBJ_NAME;
					}
<VAR_OBJ_STATE>[rwxahitmlLFRWXAIMdDcCspof]+	{
					  gradmlval.num = proc_object_mode_conv(yytext);
					  return OBJ_MODE;
					}
<IDTRANS_STATE>[_a-zA-Z0-9.-]{1,64}	{
					  gradmlval.string = gr_strdup(yytext);
					  return ID_NAME;
					}
"user_transition_allow"			{
					  BEGIN(IDTRANS_STATE);
					  return USER_TRANS_ALLOW;
					}
"user_transition_deny"			{
					  BEGIN(IDTRANS_STATE);
					  return USER_TRANS_DENY;
					}
"group_transition_allow"		{
					  BEGIN(IDTRANS_STATE);
					  return GROUP_TRANS_ALLOW;
					}
"group_transition_deny"			{
					  BEGIN(IDTRANS_STATE);
					  return GROUP_TRANS_DENY;
					}
"role"					{
					  BEGIN(ROLE_STATE);
					  return ROLE;
					}
"domain"				{
					  BEGIN(DOMAIN_STATE);
					  return DOMAIN;
					}
"role_allow_ip"				{
					  BEGIN(IPIP_STATE);
					  return ROLE_ALLOW_IP;
					}
"role_transitions"			{
					  BEGIN(ROLETRANS_STATE);
					  return ROLE_TRANSITION;
					}
"subject"				{
					  BEGIN(SUBJECT_STATE);
					  return SUBJECT;
					}
"connect"				{
					  BEGIN(IPIP_STATE);
					  return CONNECT;
					}
"bind"					{
					  BEGIN(IPIP_STATE);
					  return BIND;
					}
"ip_override"				{
					  BEGIN(IPONLY_STATE);
					  return IPOVERRIDE;
					}
"sock_allow_family"			{
					  BEGIN(FAMILY_STATE);
					  return SOCKALLOWFAMILY;
					}
"include"[ \t]*[<][/].*[>]		{
					  gr_line = strchr(yytext, '/');
					  *(gr_line + strlen(gr_line) - 1) = '\0';
					  add_include(gr_line);					  
					}
<CAP_STATE>"audit"|"suppress"		{
					  gradmlval.string = gr_strdup(yytext);
					  return AUDIT;
					}
[+-]"CAP_"[_A-Z]+			{
					  BEGIN(CAP_STATE);
					  gradmlval.string = gr_strdup(yytext);
					  return CAP_NAME;
					}
[+-]"PAX_"[_A-Z]+			{
					  gradmlval.string = gr_strdup(yytext);
					  return PAX_NAME;
					}
"RES_"[A-Z]+				{
					  BEGIN(RES_STATE);
					  gradmlval.string = gr_strdup(yytext);
					  return RES_NAME;
					}

([/]|$[(])[^ \t\n]*				{
					  gradmlval.string = process_string_replace(yytext);
					  if (strstr(gradmlval.string, "//") || strstr(gradmlval.string, "/./") || strstr(gradmlval.string, "/../"))
						gradmerror("invalid pathname error");
					  return OBJ_NAME;
					}
["]([/]|$[(]).*["]				{
					  gr_line = yytext;
					  gr_line++;
					  *(gr_line + strlen(gr_line) - 1) = '\0';
					  gradmlval.string = process_string_replace(gr_line);
					  if (strstr(gradmlval.string, "//") || strstr(gradmlval.string, "/./") || strstr(gradmlval.string, "/../"))
						gradmerror("invalid pathname error");
					  return OBJ_NAME;
					}
$HOME[/]?[^ \t\n]*			{
					  gradmlval.string = gr_strdup(yytext);
					  if (strstr(gradmlval.string, "//") || strstr(gradmlval.string, "/./") || strstr(gradmlval.string, "/../"))
						gradmerror("invalid pathname error");
					  return OBJ_NAME;
					}
["]$HOME[/]?.*["]			{
					  gr_line = yytext;
					  gr_line++;
					  *(gr_line + strlen(gr_line) - 1) = '\0';
					  gradmlval.string = gr_strdup(gr_line);
					  if (strstr(gradmlval.string, "//") || strstr(gradmlval.string, "/./") || strstr(gradmlval.string, "/../"))
						gradmerror("invalid pathname error");
					  return OBJ_NAME;
					}
[rwxahitmlLFRWXAIMcCdDspof]+		{
					  gradmlval.num = proc_object_mode_conv(yytext);
					  return OBJ_MODE;
					}
[|&()-]					{
						return *yytext;
					}
<*>[{}]					;
<<EOF>>					{
					  if (is_eof())
						yyterminate();
					}
<*>.					{ gradmerror("invalid character"); }

%%

void push_include(unsigned long linenum, YY_BUFFER_STATE buffer,
		  FILE *file, char *name)
{
	int sp = main_stack->sp;

	main_stack->stack = realloc(main_stack->stack, (1 + main_stack->sp) * sizeof(struct include_entry *));
	if (main_stack->stack == NULL)
		failure("realloc");
	main_stack->stack[sp] = calloc(1, sizeof(struct include_entry));
	if (main_stack->stack[sp] == NULL)
		failure("calloc");
	main_stack->stack[sp]->sp = -1;
	main_stack->stack[sp]->lineno = linenum;
	main_stack->stack[sp]->file = gradmin;
	main_stack->stack[sp]->name = current_acl_file;
	main_stack->stack[sp]->buffer = YY_CURRENT_BUFFER;

	return;
}

void add_include(char *includename)
{
	struct stat fstat;
	FILE *tmpfile;
	struct dirent **namelist;
	struct include_entry *last = NULL;
	struct include_entry *first = NULL;
	struct include_entry *tmp = NULL;
	char *path;
	int n, i;
	int sp;

	sp = ++main_stack->sp;

	if (sp >= MAX_INCLUDE_DEPTH) {
		fprintf(stderr, "Includes too deep while trying to process "
				"%s\n", includename);
		exit(EXIT_FAILURE);
	}

	if (stat(includename, &fstat)) {
		fprintf(stderr, "Unable to access included path: %s.\n"
				"Error: %s\n", includename, strerror(errno));
		exit(EXIT_FAILURE);
	}

	push_include(lineno, YY_CURRENT_BUFFER, gradmin, current_acl_file);
	lineno = 1;

	if (!S_ISDIR(fstat.st_mode))
		goto not_a_dir;

	n = scandir(includename, &namelist, 0, alphasort);
	if (n < 3)
		return;

	for (i = 0; i < n; i++) {
		if (!strcmp(namelist[i]->d_name, ".") || !strcmp(namelist[i]->d_name, "..") ||
		    !strcmp(namelist[i]->d_name+strlen(namelist[i]->d_name)-1, "~"))
			continue;
		tmp = calloc(1, sizeof(struct include_entry));
		if (tmp == NULL)
			failure("calloc");
		
		path = calloc(1, strlen(includename) + strlen(namelist[i]->d_name) + 2);
		if (path == NULL)
			failure("calloc");

		sprintf(path, "%s/%s", includename, namelist[i]->d_name);

		if (stat(path, &fstat)) {
			fprintf(stderr, "Unable to access included path: %s.\n"
					"Error: %s\n", includename, strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (S_ISDIR(fstat.st_mode)) {
			/* ignore the .svn and CVS directories */
		    	if (!strcmp(namelist[i]->d_name, ".svn") || !strcmp(namelist[i]->d_name, "CVS")) {
				free(tmp);
				free(path);
				continue;
			}
			fprintf(stderr, "Including the nested directory %s is not currently supported.\n", path);
			exit(EXIT_FAILURE);
		}
		tmp->sp = -1;
		tmp->name = path;
		tmp->lineno = 1;

		if (last)
			last->next = tmp;
		last = tmp;
		if (first == NULL)
			first = tmp;
	}

	main_stack->stack[main_stack->sp]->dirents = first->next;	
	path = first->name;

	change_current_acl_file(path);
	tmpfile = fopen(path, "r");

	if (!tmpfile) {
		fprintf(stderr, "Unable to open included file: %s\n", path);
		exit(EXIT_FAILURE);
	}

	gradmin = tmpfile;
	yy_switch_to_buffer(yy_create_buffer(gradmin, YY_BUF_SIZE));
	return;

not_a_dir:
	tmpfile = fopen(includename, "r");

	if (!tmpfile) {
		fprintf(stderr, "Unable to open included file: %s\n",
			includename);
		exit(EXIT_FAILURE);
	}

	change_current_acl_file(includename);
	gradmin = tmpfile;
	yy_switch_to_buffer(yy_create_buffer(gradmin, YY_BUF_SIZE));

	return;
}

int is_eof(void)
{
	struct include_entry *tmp = NULL;

	fclose(gradmin);

	if (main_stack->sp < 0)
		return 1;

	tmp = main_stack->stack[main_stack->sp];
	if (tmp->dirents != NULL) {
		tmp = tmp->dirents;
		main_stack->stack[main_stack->sp]->dirents = tmp->next;
		change_current_acl_file(tmp->name);
		yy_delete_buffer(YY_CURRENT_BUFFER);
		gradmin = fopen(tmp->name, "r");
		if (gradmin == NULL) {
			fprintf(stderr, "Unable to open included file: %s\n", tmp->name);
			exit(EXIT_FAILURE);
		}
		yy_switch_to_buffer(yy_create_buffer(gradmin, YY_BUF_SIZE));
		return 0;
	} else if (!strcmp(main_stack->stack[main_stack->sp]->name, current_acl_file))
		return 1;

	tmp = main_stack->stack[main_stack->sp];

	change_current_acl_file(tmp->name);
	yy_delete_buffer(YY_CURRENT_BUFFER);
	lineno = tmp->lineno;
	gradmin = tmp->file;
	yy_switch_to_buffer(tmp->buffer);

	if (main_stack->sp > 0)
		main_stack->sp--;

	return 0;
}

int gradmwrap(void)
{
	return 1;
}

int gradmerror(char *s)
{
	fflush(stderr);  
	fprintf(stderr, "\"%s\" caused a %s on line %lu of %s\n", yytext, s,
		lineno, current_acl_file);
	exit(EXIT_FAILURE);
}

static void no_coredump(void)
{
	struct rlimit rlim;

	rlim.rlim_cur = 0;
	rlim.rlim_max = 0;

	setrlimit(RLIMIT_CORE, &rlim);

	return;
}

static void tailor_to_kernel(void)
{
	struct utsname buf;

	uname(&buf);

	if ((strlen(buf.release) < 3) || (buf.release[2] == '4'))
		is_24_kernel = 1;
	else
		is_24_kernel = 0;

	return;
}

#ifdef GRADM_DEBUG
void show_policy(void) {
	struct file_acl *filp;
	struct ip_acl *ipp;
	struct proc_acl *proc;
	struct role_acl *rolp;
	struct role_transition *rolet;
	int i;

	for (rolp = current_role;rolp;rolp=rolp->prev) {
	printf("ROLE: %s type:%s uid/gid:%u\n", rolp->rolename,
		rolp->roletype & GR_ROLE_SPECIAL ? "special" :
		rolp->roletype & GR_ROLE_USER ? "user" :
		rolp->roletype & GR_ROLE_GROUP ? "group" :
		rolp->roletype & GR_ROLE_DEFAULT ? "default" : "",
		rolp->uidgid);
	printf("\tTRANSITIONS:");
	for (rolet = rolp->transitions; rolet; rolet=rolet->prev)
		printf(" %s", rolet->rolename);
	printf("\n");
	for (proc = rolp->hash->first;proc;proc=proc->prev) {
		printf("\tSUBJECT: %s dev:%lu inode:%lu mode:%lu c_raise:%x c_drop:%x\n",
			proc->filename, proc->dev, proc->inode, proc->mode, cap_invert(proc->cap_drop),
			proc->cap_drop);
		if (proc->user_trans_num > 0) {
			printf("\tUSER_TRANSITIONS_");
			if (proc->user_trans_type & GR_ID_ALLOW)
				printf("ALLOW:");
			else
				printf("DENY:");
			for (i = 0; i < proc->user_trans_num; i++)
				printf(" %u", proc->user_transitions[i]);
			printf("\n");
		}
		if (proc->group_trans_num > 0) {
			printf("\tGROUP_TRANSITIONS_");
			if (proc->group_trans_type & GR_ID_ALLOW)
				printf("ALLOW:");
			else
				printf("DENY:");
			for (i = 0; i < proc->group_trans_num; i++)
				printf(" %u", proc->group_transitions[i]);
			printf("\n");
		}
		for (i = 0; i < proc->ip_num; i++) {
			char ipaddr[4];
			int c;
			int netmask = 0;

			ipp = *(proc->ips + i);
			memcpy(&ipaddr, &(ipp->addr), sizeof(ipaddr));
			for (c = 0; c < 32; c++)
				if (ipp->addr & (1 << c))
					netmask++;
			if (ipp->mode &= GR_IP_CONNECT)
				printf("\t\tCONNECT %s %u.%u.%u.%u/%u:%d-%d", ipp->mode & GR_IP_INVERT ? "!" : "", ipaddr[0], ipaddr[1], ipaddr[2], ipaddr[3], netmask, ipp->low, ipp->high);
			else
				printf("\t\tBIND %s %u.%u.%u.%u/%u:%d-%d", ipp->mode & GR_IP_INVERT ? "!" : "", ipaddr[0], ipaddr[1], ipaddr[2], ipaddr[3], netmask, ipp->low, ipp->high);

			for (c = 1; c < 5; c++) {
				if (ipp->type & (1 << c)) {
					switch (c) {
					case SOCK_RAW:
						printf(" raw_sock");
						break;
					case SOCK_DGRAM:
						printf(" dgram");
						break;
					case SOCK_STREAM:
						printf(" stream");
						break;
					case SOCK_RDM:
						printf(" rdm");
						break;
					}
				}
			}
			for (c = 0; c < 256; c++) {
				if (ipp->proto[c / 32] & (1 << (c % 32))) {
					if (c == IPPROTO_RAW)
						printf(" raw_proto");
					else {
						struct protoent *proto;
						proto = getprotobynumber(c);
					if(proto)
						printf(" %s", proto->p_name);
					else
						printf(" %d", c);
					}
				}
			}
			printf("\n");
		}
		for (filp = proc->hash->first;filp;filp=filp->prev)
                        printf("\t\tOBJECT: %s dev:%lu inode:%lu mode:%lu\n", filp->filename, filp->dev, filp->inode, filp->mode);
		for (i=0;i<GR_NLIMITS;i++)
			if (proc->resmask & (1 << i))
				printf("\t\t%s: soft: %lu hard: %lu\n", rlim_table[i], proc->res[i].rlim_cur, proc->res[i].rlim_max);
	}
	}
}
#endif

int main(int argc, char *argv[])
{
	if (geteuid() != getuid()) {
		fprintf(stderr, "gradm is not meant to run suid root.\n");
		exit(EXIT_FAILURE);
	}

	special_role_uid = 0;
	
	tailor_to_kernel();
#ifndef GRADM_DEBUG
	no_coredump();
#endif

	main_stack = &include_stack;
	memset(main_stack, 0, sizeof(struct include_entry));
	main_stack->sp = -1;
	
	init_variables();

	parse_args(argc, argv);

#ifdef GRADM_DEBUG
	show_policy();
#endif
	return 0;
}

