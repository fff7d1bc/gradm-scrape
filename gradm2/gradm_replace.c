#include "gradm.h"

typedef struct _replace_string_entry
{
	struct _replace_string_entry *next;
	char *name;
	char *replacewith;
} replace_string_entry;

static replace_string_entry *replace_list;

char *lookup_replace_string(char *name)
{
	replace_string_entry *tmp;

	for (tmp = replace_list; tmp; tmp = tmp->next) {
		if (!strcmp(tmp->name, name))
			return tmp->replacewith;
	}

	return NULL;
}

/* called with already strdup'd strings */
void add_replace_string(char *name, char *replacewith)
{
	replace_string_entry *entry;
	replace_string_entry *tmp;

	/* replace an existing entry if the name is redefined */
	for (entry = replace_list; entry; entry = entry->next) {
		if (!strcmp(entry->name, name)) {
			free(entry->replacewith);
			entry->replacewith = replacewith;
			return;
		}
		if (entry->next == NULL)
			break;
	}

	tmp = malloc(sizeof(replace_string_entry));
	if (tmp == NULL)
		failure("malloc");

	tmp->next = NULL;
	tmp->name = name;
	tmp->replacewith = replacewith;
	
	if (replace_list == NULL)
		replace_list = tmp;
	if (entry != NULL)
		entry->next = tmp;

	return;
}

/* returns newly allocated string */
char *process_string_replace(char *str)
{
	char *p, *p2;
	char *replacewith;
	char *newstr;
	unsigned int newlen;

	p = strstr(str, "$(");
	if (p == NULL)
		goto normal_str;
	p2 = strchr(p, ')');
	if (p2 == NULL) {
		fprintf(stderr, "Error: Missing terminating \")\" for symbol on line %ld "
				"of %s.\n", lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}
	*p2 = '\0';

	replacewith = lookup_replace_string(p + 2);
	if (replacewith == NULL) {
		fprintf(stderr, "Error: Undefined symbol \"%s\" on line %ld "
				"of %s.\n", p + 2, lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	*p = '\0';

	newlen = strlen(str) + strlen(p2 + 1) + strlen(replacewith);
	newstr = malloc(newlen + 1);
	strcpy(newstr, str);
	strcat(newstr, replacewith);
	strcat(newstr, p2 + 1);
	newstr[newlen] = '\0';

	*p = '$';
	*p2 = ')';

	if (newstr[0] != '/' && (newlen < 5 || strncmp(newstr, "$HOME", 5))) {
		fprintf(stderr, "Error: Malformed path on line %ld of %s.\n", 
				lineno, current_acl_file);
		exit(EXIT_FAILURE);
	}

	return newstr;
normal_str:
	return strdup(str);
}
