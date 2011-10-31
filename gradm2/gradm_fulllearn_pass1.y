%{
#include "gradm.h"
extern int fulllearn_pass1lex(void);

extern struct gr_learn_group_node **role_list;
%}

%union {
	char * string;
	unsigned long num;
}

%token <num> NUM IPADDR FILENAME ROLENAME USER GROUP
%type <num> filename id_type

%%

learn_logs:	learn_log
	|	learn_logs learn_log
	;

filename:	/*empty*/	{ $$ = 1; }
	|	FILENAME	{ $$ = 1; }
	;

id_type:	USER
	|	GROUP
	;

learn_log:
		error
	|	ROLENAME ':' NUM ':' NUM ':' NUM ':' filename ':' filename ':' NUM ':' NUM ':' filename ':' NUM ':' IPADDR
		{
			char *user;
			char *group;
			uid_t uid;
			gid_t gid;

			uid = $5;
			gid = $7;

			user = gr_get_user_name(uid);
			group = gr_get_group_name(gid);

			if (user && group)
				insert_user(&role_list, user, group, uid, gid);
		}		
	|	ROLENAME ':' NUM ':' NUM ':' NUM ':' filename ':' filename ':' IPADDR ':' NUM ':' NUM ':' NUM ':' NUM ':' IPADDR
		{
			char *user;
			char *group;
			uid_t uid;
			gid_t gid;

			uid = $5;
			gid = $7;

			user = gr_get_user_name(uid);
			group = gr_get_group_name(gid);

			if (user && group)
				insert_user(&role_list, user, group, uid, gid);
		}
	|	ROLENAME ':' NUM ':' NUM ':' NUM ':' filename ':' filename ':' id_type ':' NUM ':' NUM ':' NUM ':' IPADDR
		{
			char *user;
			char *group;
			uid_t uid;
			gid_t gid;

			uid = $5;
			gid = $7;

			user = gr_get_user_name(uid);
			group = gr_get_group_name(gid);

			if (user && group)
				insert_user(&role_list, user, group, uid, gid);
		}
	;
%%
