#include "gradm.h"

struct object_variable {
	char *symname;
	struct var_object *object;
};

static struct object_variable *symtab = NULL;
static unsigned int symtab_size = 0;

void interpret_variable(struct var_object *var)
{
	struct var_object *tmp;
	for (tmp = var; tmp->prev; tmp = tmp->prev)
		;

	for (; tmp; tmp = tmp->next) {
		add_proc_object_acl(current_subject, tmp->filename, tmp->mode, GR_FEXIST);
	}

	return;
}

struct var_object * intersect_objects(struct var_object *var1, struct var_object *var2)
{
	struct var_object *tmpvar1, *tmpvar2, *retvar = NULL;

	for (tmpvar1 = var1; tmpvar1; tmpvar1 = tmpvar1->prev) {
		for (tmpvar2 = var2; tmpvar2; tmpvar2 = tmpvar2->prev) {
			if (!strcmp(tmpvar1->filename, tmpvar2->filename)) {
				add_var_object(&retvar, tmpvar1->filename, tmpvar1->mode & tmpvar2->mode);
				break;
			}
		}
	}

	return retvar;
}

struct var_object * union_objects(struct var_object *var1, struct var_object *var2)
{
	struct var_object *tmpvar1, *tmpvar2, *retvar = NULL;
	int found_dupe = 0;

	for (tmpvar1 = var1; tmpvar1; tmpvar1 = tmpvar1->prev) {
		found_dupe = 0;
		for (tmpvar2 = var2; tmpvar2; tmpvar2 = tmpvar2->prev) {
			if (!strcmp(tmpvar1->filename, tmpvar2->filename)) {
				add_var_object(&retvar, tmpvar1->filename, tmpvar1->mode | tmpvar2->mode);
				found_dupe = 1;
				break;
			}
		}
		if (!found_dupe)
			add_var_object(&retvar, tmpvar1->filename, tmpvar1->mode);
	}

	for (tmpvar2 = var2; tmpvar2; tmpvar2 = tmpvar2->prev) {
		found_dupe = 0;
		for (tmpvar1 = var1; tmpvar1; tmpvar1 = tmpvar1->prev) {
			if (!strcmp(tmpvar1->filename, tmpvar2->filename)) {
				found_dupe = 1;
				break;
			}
		}
		if (!found_dupe)
			add_var_object(&retvar, tmpvar2->filename, tmpvar2->mode);
	}

	return retvar;
}

struct var_object * differentiate_objects(struct var_object *var1, struct var_object *var2)
{
	struct var_object *tmpvar1, *tmpvar2, *retvar = NULL;
	int found_dupe = 0;
	char *path;

	for (tmpvar1 = var1; tmpvar1; tmpvar1 = tmpvar1->prev) {
		path = calloc(strlen(tmpvar1->filename) + 1, sizeof(char));
		if (!path)
			failure("calloc");
		strcpy(path, tmpvar1->filename);
		found_dupe = 0;
		do {
			for (tmpvar2 = var2; tmpvar2; tmpvar2 = tmpvar2->prev) {
				if (!strcmp(path, tmpvar2->filename)) {
					found_dupe = 1;
					add_var_object(&retvar, tmpvar1->filename, tmpvar1->mode &= ~tmpvar2->mode);
					goto done;
				}
			}
		} while(parent_dir(tmpvar1->filename, &path));
done:
		if (!found_dupe)
			add_var_object(&retvar, tmpvar1->filename, tmpvar1->mode);
		free(path);
	}

	return retvar;
}

void add_var_object(struct var_object **object, char *name, u_int32_t mode)
{
	struct var_object *v;

	v = (struct var_object *) calloc(1, sizeof(struct var_object));

	if (!v)
		failure("calloc");

	if (*object)
		(*object)->next = v;

	v->prev = *object;

	v->filename = name;
	v->mode = mode;

	*object = v;

	return;
}

struct var_object * sym_retrieve(char *symname)
{
	unsigned int i;

	for (i = 0; i < symtab_size; i++)
		if (!strcmp(symname, symtab[i].symname))
			return symtab[i].object;
		

	return NULL;
}

void sym_store(char *symname, struct var_object *object)
{
	symtab_size++;

	symtab = realloc(symtab, symtab_size * sizeof(struct object_variable));

	if (symtab == NULL)
		failure("realloc");

	symtab[symtab_size - 1].symname = symname;
	symtab[symtab_size - 1].object = object;

	return;
}
