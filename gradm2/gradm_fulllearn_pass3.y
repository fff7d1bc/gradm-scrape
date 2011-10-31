%{
#include "gradm.h"
extern int fulllearn_pass3lex(void);

extern struct gr_learn_group_node *the_role_list;
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
			struct gr_learn_file_node *subjlist = NULL;
			struct gr_learn_file_node *subject = NULL;
			uid_t uid;
			gid_t gid;
			u_int32_t mode;
			unsigned long res1, res2;
			char *filename = $9;

			/* check if we have an inherited learning subject */
			if (strcmp($11, "/")) {
				filename = $11;
				free($9);
			} else
				free($11);

			uid = $5;
			gid = $7;
			mode = $19;
			res1 = $13;
			res2 = $15;

			match_role(the_role_list, uid, gid, &group, &user);
			/* only add objects for the role currently in memory */
			if ((current_learn_rolemode == GR_ROLE_GROUP && group && !strcmp(group->rolename, current_learn_rolename)) ||
			    (current_learn_rolemode == GR_ROLE_USER && user && !strcmp(user->rolename, current_learn_rolename)))
			{
			if (user)
				subjlist = user->subject_list;
			else if (group)
				subjlist = group->subject_list;

			if (subjlist)
				subject = match_file_node(subjlist, filename);
			/* only learn objects for current subject in memory */
			if (subject && !strcmp(subject->filename, current_learn_subject)) {
			if (subject && strcmp($17, ""))
				insert_learn_object(subject, conv_filename_to_struct($17, mode | GR_FIND));
			else if (subject && strlen(filename) > 1 && !res1 && !res2) {
				if (subject->subject == NULL) {
					subject->subject = calloc(1, sizeof(struct gr_learn_subject_node));
					if (subject->subject == NULL)
						failure("calloc");
				}
				cap_raise(subject->subject->cap_raise, mode);
			}
			}
			}
			free(filename);
			free($17);
		}		
	|	ROLENAME ':' NUM ':' NUM ':' NUM ':' filename ':' filename ':' IPADDR ':' NUM ':' NUM ':' NUM ':' NUM ':' IPADDR
		{
			struct gr_learn_group_node *group = NULL;
			struct gr_learn_user_node *user = NULL;
			struct gr_learn_file_node *subjlist = NULL;
			struct gr_learn_file_node *subject = NULL;
			uid_t uid;
			gid_t gid;
			u_int32_t addr;
			u_int16_t port;
			u_int8_t mode, proto, socktype;
			char *filename = $9;

			/* check if we have an inherited learning subject */
			if (strcmp($11, "/")) {
				filename = $11;
				free($9);
			} else
				free($11);

			uid = $5;
			gid = $7;
			mode = $19;

			addr = $13;

			port = $15;
			socktype = $17;
			proto = $19;
			mode = $21;

			match_role(the_role_list, uid, gid, &group, &user);
			/* only add objects for the role currently in memory */
			if ((current_learn_rolemode == GR_ROLE_GROUP && group && !strcmp(group->rolename, current_learn_rolename)) ||
			    (current_learn_rolemode == GR_ROLE_USER && user && !strcmp(user->rolename, current_learn_rolename)))
			{

			if (user)
				subjlist = user->subject_list;
			else if (group)
				subjlist = group->subject_list;

			if (subjlist)
				subject = match_file_node(subjlist, filename);
			/* only learn objects for current subject in memory */
			if (subject && !strcmp(subject->filename, current_learn_subject)) {
			if (subject && mode == GR_IP_CONNECT)
				insert_ip(&(subject->connect_list), addr, port, proto, socktype);
			else if (subject && mode == GR_IP_BIND)
				insert_ip(&(subject->bind_list), addr, port, proto, socktype);
			else if (subject && mode == GR_SOCK_FAMILY) {
				if (subject->subject == NULL) {
					subject->subject = calloc(1, sizeof(struct gr_learn_subject_node));
					if (subject->subject == NULL)
						failure("calloc");
				}
				subject->subject->sock_families[port / 32] |= (1 << (port % 32));
			}
			}
			}
			free(filename);
		}
	| ROLENAME ':' NUM ':' NUM ':' NUM ':' filename ':' filename ':' id_type ':' NUM ':' NUM ':' NUM ':' IPADDR
		{
			struct gr_learn_group_node *group = NULL;
			struct gr_learn_user_node *user = NULL;
			struct gr_learn_file_node *subjlist = NULL;
			struct gr_learn_file_node *subject = NULL;
			uid_t uid;
			gid_t gid;
			unsigned int real, eff, fs;
			char *filename = $9;

			/* check if we have an inherited learning subject */
			if (strcmp($11, "/")) {
				filename = $11;
				free($9);
			} else
				free($11);

			uid = $5;
			gid = $7;
			real = $15;
			eff = $17;
			fs = $19;

			match_role(the_role_list, uid, gid, &group, &user);
			/* only add objects for the role currently in memory */
			if ((current_learn_rolemode == GR_ROLE_GROUP && group && !strcmp(group->rolename, current_learn_rolename)) ||
			    (current_learn_rolemode == GR_ROLE_USER && user && !strcmp(user->rolename, current_learn_rolename)))
			{

				if (user)
					subjlist = user->subject_list;
				else if (group)
					subjlist = group->subject_list;

				if (subjlist)
					subject = match_file_node(subjlist, filename);
				/* only learn objects for current subject in memory */
				if (subject && !strcmp(subject->filename, current_learn_subject)) {
					if (subject && $13 == USER)
						insert_learn_id_transition(&(subject->user_trans_list), real, eff, fs);
					else if (subject && $13 == GROUP)
						insert_learn_id_transition(&(subject->group_trans_list), real, eff, fs);
				}
			}
			free(filename);
		}
	;
%%
