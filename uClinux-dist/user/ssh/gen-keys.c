#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>


/* This little program is a wrapper for the ssh key-gen program that produces
 * ssh keys as required.  The basic outline is simple, keys will be produced
 * at boot time for sshd only if they don't already exist.  For ssh the path
 * is slightly more complex, keys will be created every boot unless sshd is
 * also installed in which case its behaviour will override.
 *
 * In addition, the flash file system will be synced if sshd is enabled.
 * This means that sshd will only use a single set of keys which is good
 * because ssh causes pain if the daemon it is connecting to changes its
 * keys.
 */


/* Where we end up installing our key files */
#define BASE_DIR	"/etc/config/"

/* List of file names to mangle */
static char *files[2] = {
	"ssh_host_key",
	"ssh_host_dsa_key"
};

	
#ifdef INCLUDE_SSHD
/* Check if the key files are alreayd there or not */
static inline int check_files(void) {
int		  i;
struct stat	  st;
char		  fname[40];
	for (i=0; i<2; i++) {
		strcpy(fname, BASE_DIR);
		strcpy(fname+sizeof(BASE_DIR)-1, files[i]);
		if (-1 == stat(fname, &st))
			return 0;
		strcat(fname, ".pub");
		if (-1 == stat(fname, &st))
			return 0;
	}
	return 1;
}
#endif


/* Remove all key files.  The key generator fails if they're already there */
static inline void remove_files(void) {
int		  i;
char		  fname[40];
	for (i=0; i<2; i++) {
		strcpy(fname, BASE_DIR);
		strcpy(fname+sizeof(BASE_DIR)-1, files[i]);
		unlink(fname);
		strcat(fname+sizeof(BASE_DIR)-1, ".pub");
		unlink(fname);
	}
}


/* Exec the key generation program with the specified args */
static void exec(char *const av[]) {
extern char	**environ;
int		  status;
pid_t		  pid;
	pid = vfork();
	if (pid == 0) {
		/* Child */
		execve("/bin/ssh-keygen", av, environ);
		_exit(0);
	} else if (pid != -1) {
		waitpid(pid, &status, 0);
	}
}


/* Scan through and generate the appropriate keys */
static inline void gen_files(void) {
char		 *av[12];
int		  ac;
char		  fname[40];
	ac = 0;
	av[ac++] = "ssh-keygen";
	av[ac++] = "-q";
	av[ac++] = "-f";
	strcpy(fname, BASE_DIR);
	strcpy(fname+sizeof(BASE_DIR)-1, files[0]);
	av[ac++] = fname;
	av[ac++] = "-C";
	av[ac++] = "";
	av[ac++] = "-N";
	av[ac++] = "";
	av[ac] = NULL;
	exec(av);

	/* Cleverly re-use existing args */
	strcpy(fname+sizeof(BASE_DIR)-1, files[1]);
	av[ac++] = "-d";
	av[ac] = NULL;
	exec(av);
}


#ifdef INCLUDE_SSHD
/* Write back our config file system */
static inline void sync_files(void) {
char		  value[16];
pid_t		  pid;
int		  fd;
	fd = open("/var/run/flatfsd.pid", O_RDONLY);
	if (fd != -1) {
		if (read(fd, value, sizeof(value)) > 0 &&
				(pid = atoi(value)) > 1)
			kill(pid, SIGUSR1);
		close(fd);
	}
}
#endif


/* The main driver routine */
int main(int argc, char *argv[]) {
	sleep(10);	
#ifdef INCLUDE_SSHD
	if (check_files())
		return 0;
#endif
	remove_files();
	gen_files();
#ifdef INCLUDE_SSHD
	sync_files();
#endif
	return 0;
}
