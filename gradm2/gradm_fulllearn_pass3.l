%{
#include "gradm.h"
#include "fulllearn_pass3.tab.h"

void fulllearn_pass3error(const char *s);
int fulllearn_pass3wrap(void);
static struct in_addr ip;
%}

ROLENAME ^[_a-zA-Z0-9.-]{1,64}
NOTAFILE [a-z]+"["[0-9]+"]"
NUM [-]?[0-9]+
FILENAME [/][^\t\n]*
IPADDR [0-9]{1,3}"."[0-9]{1,3}"."[0-9]{1,3}"."[0-9]{1,3}

%option nounput

%x ERROR

%%

"u"					{
					  fulllearn_pass3lval.num = USER;
					  return USER;
					}
"g"					{
					  fulllearn_pass3lval.num = GROUP;
					  return GROUP;
					}
{NUM}					{
					  fulllearn_pass3lval.num = atol(yytext);
					  return NUM;
					}
{NOTAFILE}				{
					  fulllearn_pass3lval.string = gr_strdup("/proc");
					  return FILENAME;
					}
{ROLENAME}				{
					  /* not used in grammar */
					  return ROLENAME;
					}
{FILENAME}				{
					  fulllearn_pass3lval.string = gr_strdup(yytext);
					  return FILENAME;
					}
{IPADDR}				{
					  if (inet_aton(yytext, &ip))
						fulllearn_pass3lval.num = ip.s_addr;
					  else
						fulllearn_pass3lval.num = 0;
					  return IPADDR;
					}
[\t]					{ return ':'; }
.					;
%%

void fulllearn_pass3error(const char *s) { return; }
int fulllearn_pass3wrap(void) { return 1; }
