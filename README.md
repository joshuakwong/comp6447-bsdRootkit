# COMP6447 Rootkit

This is a kernel rootkit that will run on FreeBSS 12.0. This rootkit is mostly based on the book <b>Designing BSD Rootkits</b>. Most parts of the rootkit are achieved by <b>Loadable Kernel Module</b>, a small portion of the rootkit functionality are implemented in userland level, details are mentioned below.

There are 4 parts in this assignment, namely <b>install</b>, <b>elevate</b>, <b>log</b> and <b>remote</b>

## tldr; Instruction:
Copy and paste the entire directory and put it in the target machine, then run respective scripts

### ./install
- compile rootkit on the target machine to ensure compatability
- install the rootkit as kernel loadable modules
- set up rootkit persistence

### ./elevate
- priv esclation
- triggered by `mkdir 5c49bd22eb6767f002f6236fd09a84eef560443d7a5fdbe4be3a344ea127bf78`
- the directory is then removed

### ./log
- exfiltrate contents generated by key logger
- to be run on attacker's machine
- <b>doesnt work, might try to fix it in the future</b>

### remote
- pops a shell with root permission :)

--------

## Writeup

## Rootkit Functionality
### Installation
Our rootkit consists of two loadable kernel modules. Our main KLD, _'trivial'_, hooks several syscalls to set up the various features of our Rootkit as outlined below:

| Syscall       | Purpose
|---------------|---------------
| read          | Keylogging
| open          | Concealment of file contents
| getdirentries | Hiding files in the file system
| rename        | Preventing changes to cron file

The second KLD, _'hideProc'_, adds a new syscall to the syscall table that, when triggered, hides certain processes from the output of `ps`. This is loaded separately to avoid a monolithic KLD, however, _'trivial'_ is still responsible for hiding this second kernel module.

Our installation process involves compiling the kernel modules and shell binary on the target machine. This facilitates the ability to write the specified 'remote' IP address into the binary for our reverse shell.

The rootkit installation process also sets up persistence by creating a crontab file to load the two kernel modules on startup and launch the reverse shell daemon.

Once the installation is complete, the entire src directory is removed. The three files that must remain on the system are the `.ko` files for _trivial_ and _hideProc_, and the binary for the reverse shell. These are placed in a directory called `6d4c9cf5e022a07ea8013a4b07a30a88270c65dfd5223ccc3964d9a7b4525008`, which is hidden from `ls` output. This makes it appear that the only file left is the elevate script (as required for the marking process).

### Privilege Escalation
Privilege escalation is performed by modifying the `ucred` data structure from the kernel module. This modifies the `cr_uid` and `cr_ruid` to be root (0) for the current thread, turning the current user into root.

Privilege escalation can be triggered by executing `mkdir 5c49bd22eb6767f002f6236fd09a84eef560443d7a5fdbe4be3a344ea127bf78`. Whilst this is still using the mkdir hook, the filename is obscure enough that it is extremely unlikely to accidentally be triggered. However, a future improvement would be to use a different trigger (such as hooking a different or custom syscall that is called less frequently).

### Concealment
* Network Activity
    * We were unable to implement port hiding
* The two kernel modules are hidden from the output of kldstat
    * The KLD object count also remains the same after loading the modules
* File Hiding is achieved through hooking the getdirentries syscall
    * The `.ko` file for the main KLD is hidden in the file system
    * It is hidden from `ls` output through the getdirentries hook
    * The keylogger data file is hidden from `ls` output
* The crontab file for persistence is hidden:
    * If the user tries to read the file, it returns /dev/null instead.
    * if the user tries to rename a file to the crontab file (or uses `crontab -e` to edit the root crontab), the process will fail silently through the rename hook
    * Through the concealment mechanisms through syscall hooks, we decided that the crontab `@reboot` directive was sufficient for our persistence mechanisms, since the user is unable to read or modify the crontab file once the rootkit is loaded.
    * We use the cron of the builtin account `toor` (The 'Bourne-again Superuser'). This user has the same privileges as root, however any existing crontabs that the system administrator may have set up under the root account will not be overwritten, since we are using the toor user instead.
* Hiding Running Processes
    * Our listener for the remote shell is hidden from the running process list (i.e. output of the `ps` command).
    * We did not hide the cronjob process as this caused some stability issues, and a cron job does not look immediately suspicious.

### Keylogger Implementation
The keylogger hooks the `read` syscall. Our hook checks if the file descriptor is 0, and if so, saves a copy of the input into a buffer. It then calls the standard read syscall function.
When this buffer reaches LOGBUFLEN, it will append the data to a file at LOGPATH.
To exfil data, the target machine has an open port, if it sees the string "6447", it will start exfil data. The key log file will be compressed with `tar -cjf` to reduce size. A web server is running on remote machine, exfil will work as if it is uploading file with http packets.
Note: The exfil function works 60% of the time, sometimes it crashes mysteriously... The remaining 40% is pure luck, if the exfil doesnt work please hand mark it. Thanks :p

### Remote Shell
The remote shell is a direct shell that is listening on port \<port number> on target machine. The listener runs as a cron job that executes every minute. When executed, it waits for any connection, and when the `remote` script is ran, it will give a shell.
After every connection, remote will have to wait at most 1 minute. The remote shell is not an interactive one, so vim wouldn't work.

### Reboot Persistence
Our reboot persistence is achieved through setting up a cronjob on installation, which will trigger on reboot and reload our kernel modules. The cronjob also runs the revese shell and log exfil listener at regular intervals.

## Rootkit Detection
### Hiding from Userland Detection
* New syscall (loaded as syscall 210) hideProc(pid_t pid)
* The rev shell proc is hidden from `ps` and `top`
* Hiding from kldstat output
* File hiding & file contents concealment

### Hiding from Kernel Space Detection
Our rootkit removes the KLD items from the linked list data structure, making it impossible for the kernel to traverse this list and check for unwanted kernel modules. 

### How to Detect our Rootkit
* Network Activity: 
	* Any port scan from another machine will reveal two listening ports constantly open
	* Running commands such as `tcpdump`
a machThe listener for remote shell and exfilnmap will detect it, because we are have an opened port. The port is hidden from sockstat, but not nmap
* When the cron job starts running, there will be a proc `cron: running job (cron)` running
* The 'read' hook can cause some undesirable side effects (such as some file operations to fail every now and again). This is due to the syscall trying to write the log data to a file on disk in the middle of another action.
* Examining the syscall table will reveal that the syscall number offsets do not look 'normal' (the hooked syscalls will have numbers different to those which haven't been hooked).

### Future Improvements to Prevent Detection
* Hook character device instead of read for keylogging (this was partially implemented, but couldn't get the character data - would be interesting to pursue further)
* Change the way keylog data is stored (e.g. keep entirely in memory to prevent disk usage changes)
* Use a different persistence mechanism that is quieter (e.g. hook shutdown to add startup task, then remove on startup)
* Hide the open port from nmap, make it not respond to SYN scan

