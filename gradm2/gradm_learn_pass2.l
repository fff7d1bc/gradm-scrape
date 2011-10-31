%{
#include "gradm.h"
#include "learn_pass2.tab.h"

void learn_pass2error(const char *s);
int learn_pass2wrap(void);
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
					  learn_pass2lval.num = USER;
					  return USER;
					}
"g"					{
					  learn_pass2lval.num = GROUP;
					  return GROUP;
					}
{NUM}					{
					  learn_pass2lval.num = atol(yytext);
					  return NUM;
					}
{NOTAFILE}				{
					  learn_pass2lval.string = gr_strdup("/proc");
					  return FILENAME;
					}
{ROLENAME}				{
					  learn_pass2lval.string = gr_strdup(yytext);
					  return ROLENAME;
					}
{FILENAME}				{
					  learn_pass2lval.string = gr_strdup(yytext);
					  return FILENAME;
					}
{IPADDR}				{
					  if (inet_aton(yytext, &ip))
						learn_pass2lval.num = ip.s_addr;
					  else
						learn_pass2lval.num = 0;
					  return IPADDR;
					}
[\t]					{ return ':'; }
.					;
%%

void learn_pass2error(const char *s) { return; }
int learn_pass2wrap(void) { return 1; }
