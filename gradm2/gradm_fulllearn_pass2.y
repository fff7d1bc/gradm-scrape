%{
#include "gradm.h"
extern int fulllearn_pass2lex(void);

extern struct gr_learn_group_node **role_list;
%}

%union {
	char * string;
	unsigned long num;
}

%token <string> FILENAME ROLENAME
%token <num> NUM IPADDR USER GROUP
%type <string> filename
%type <num> id_type

%%

learn_logs:	learn_log
	|	learn_logs learn_log
	;

filename:	/*empty*/	{ $$ = gr_strdup(""); }
	|	FILENAME	{
				  if (!strcmp($1, "//"))
					$1[1] = '\0';
				  $$ = $1;
				}
	;

id_type:	USER
	|	GROUP
	;

learn_log:
		error
	|	ROLENAME ':' NUM ':' NUM ':' NUM ':' filename ':' filename ':' NUM ':' NUM ':' filename ':' NUM ':' IPADDR
		{
			struct gr_learn_group_node *group = NULL;
			struct gr_learn_user_node *user = NULL;
			uid_t uid;
			gid_t gid;
			unsigned long res1, res2;
			u_int32_t addr;
			char *filename = $9;

			/* check if we have an inherited learning subject */
			if (strcmp($11, "/")) {
				filename = $11;
				free($9);
			} else
				free($11);

			uid = $5;
			gid = $7;
			res1 = $13;
			res2 = $15;

			addr = $21;

			match_role(role_list, uid, gid, &group, &user);
	
			if (user)
				insert_ip(&(user->allowed_ips), addr, 0, 0, 0);
			else if (group)
				insert_ip(&(group->allowed_ips), addr, 0, 0, 0);
				
			if (user && ((!strcmp($17, "")  && strlen(filename) > 1 && !res1 && !res2) || is_protected_path($17, $19)))
				insert_learn_user_subject(user, conv_filename_to_struct(filename, GR_PROCFIND | GR_OVERRIDE));
			else if (group && ((!strcmp($17, "") && strlen(filename) > 1 && !res1 && !res2) || is_protected_path($17, $19)))
				insert_learn_group_subject(group, conv_filename_to_struct(filename, GR_PROCFIND | GR_OVERRIDE));

			free(filename);
			free($17);
		}		
	|	ROLENAME ':' NUM ':' NUM ':' NUM ':' filename ':' filename ':' IPADDR ':' NUM ':' NUM ':' NUM ':' NUM ':' IPADDR
		{
			struct gr_learn_group_node *group = NULL;
			struct gr_learn_user_node *user = NULL;
			uid_t uid;
			gid_t gid;
			u_int32_t addr;
			char *filename = $9;

			/* check if we have an inherited learning subject */
			if (strcmp($11, "/")) {
				filename = $11;
				free($9);
			} else
				free($11);

			uid = $5;
			gid = $7;

			addr = $23;

			match_role(role_list, uid, gid, &group, &user);

			if (user) {
				insert_ip(&(user->allowed_ips), addr, 0, 0, 0);
				insert_learn_user_subject(user, conv_filename_to_struct(filename, GR_PROCFIND | GR_OVERRIDE));
			} else if (group) {
				insert_ip(&(group->allowed_ips), addr, 0, 0, 0);
				insert_learn_group_subject(group, conv_filename_to_struct(filename, GR_PROCFIND | GR_OVERRIDE));
			}

			free(filename);
		}
	| ROLENAME ':' NUM ':' NUM ':' NUM ':' filename ':' filename ':' id_type ':' NUM ':' NUM ':' NUM ':' IPADDR
	{
		free($9);
		free($11);
	}
	;
%%
