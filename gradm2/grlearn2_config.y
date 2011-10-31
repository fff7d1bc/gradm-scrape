%{
#include "gradm.h"
extern int grlearn_configlex(void);
extern void add_always_reduce(char *str);
extern void grlearn_configerror(const char *s);

#define grlearn2_configerror grlearn_configerror
#define grlearn2_configlex grlearn_configlex
%}

%union {
	char * string;
	unsigned long num;
}

%token <string> FILENAME NOLEARN INHERITLEARN INHERITNOLEARN DONTREDUCE 
%token <string> PROTECTED HIGHPROTECTED HIGHREDUCE ALWAYSREDUCE NOALLOWEDIPS
%token <num> NUM

%%

learn_config_file:	learn_config
		|	learn_config_file learn_config
		;

learn_config:
		NOLEARN FILENAME
		{
		}
	|	INHERITLEARN FILENAME
		{
		}
	|	INHERITNOLEARN FILENAME
		{
		}
	|	DONTREDUCE FILENAME
		{
		}
	|	PROTECTED FILENAME
		{
		}
	|	HIGHREDUCE FILENAME
		{
		}
	|	ALWAYSREDUCE FILENAME
		{
			add_always_reduce($2);
		}
	|	HIGHPROTECTED FILENAME
		{
		}
	|	NOALLOWEDIPS
		{
		}
	;
%%
