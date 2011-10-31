%{
#include "gradm.h"
#ifdef IS_GRLEARN
#include "grlearn2_config.tab.h"
#define grlearn_configlval grlearn2_configlval
#else
#include "grlearn_config.tab.h"
#endif

void grlearn_configerror(const char *s);
int grlearn_configwrap(void);

%}

NUM [0-9]+
FILENAME [/][^\t\n]*

%option nounput

%x ERROR COMMENT_STATE

%%

<*>"#"					{
					  BEGIN(COMMENT_STATE);
					}
<*>"\n"					{
					  BEGIN(INITIAL);
					}
"inherit-learn"				{
					  return INHERITLEARN;
					}
"inherit-no-learn"			{
					  return INHERITNOLEARN;
					}
"no-learn"				{
					  return NOLEARN;
					}
"dont-reduce-path"			{
					  return DONTREDUCE;
					}
"high-reduce-path"			{
					  return HIGHREDUCE;
					}
"always-reduce-path"			{
					  return ALWAYSREDUCE;
					}
"protected-path"			{
					  return PROTECTED;
					}
"high-protected-path"			{
					  return HIGHPROTECTED;
					}
"dont-learn-allowed-ips"		{
					  return NOALLOWEDIPS;
					}
{NUM}					{
					  grlearn_configlval.num = atol(yytext);
					  return NUM;
					}
{FILENAME}				{
					  grlearn_configlval.string = gr_strdup(yytext);
					  return FILENAME;
					}
.					;
%%

void grlearn_configerror(const char *s) { return; }
int grlearn_configwrap(void) { return 1; }
