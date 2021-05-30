/* ////////////////////////////////////////////////////////////////////////////
				 simpleinit.c
///////////////////////////////////////////////////////////////////////////////
DESCRIPTION:	This is the Linux 'init' process.  It is invoked by the startup
		code.  It is supposed to run the script in /etc/rc, process the
		/etc/inittab file, and then run forever thereafter to make sure
		that the processes specified in the /etc/inittab file remain
		alive.

                This version of 'init' was built starting from scratch, one
                step at a time, in an effort to get the 2.4 kernel running on
                the uCdimm development board.  As received, that setup would
                run all the way through init, but would not then give a shell
                prompt or a login prompt.

REVISIONS:	200206201347 - RAC - Initial test that simply reads from stdin
				      and writes to stdout to make sure that
				      that much works when this thing gets run.
                                      It sort of worked, except the input and
                                      output wasn't synchronized properly, and
                                      there was no input line editing
                                      (backspace didn't work correctly, e.g.) 
		200206201446 - RAC - Replaced initial test with /etc/rc
				      processing and added err() for displaying
				      messages.  This seemed to work okay.
		200206201636 - RAC - Filled in everything else.  Lo and behold,
				      it worked.
//////////////////////////////////////////////////////////////////////////// */

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include "pathnames.h"

/* ////////////////////////////////////////////////////////////////////////////
			       Names for Numbers
//////////////////////////////////////////////////////////////////////////// */

#define CMDSIZ 150		// Max size of a line in inittab
#define NUMCMD 30		// Max number of lines in inittab
#define NUMTOK 20		// Max number of tokens in inittab command

/* ////////////////////////////////////////////////////////////////////////////
			  Local Structure Definitions
//////////////////////////////////////////////////////////////////////////// */

struct initline {
    pid_t	pid;				// Process ID
    char	tty[10];
    char	termcap[30];
    char	*toks[NUMTOK];
    char	line[CMDSIZ];
    };						// End 'struct initline'

/* ////////////////////////////////////////////////////////////////////////////
			   Local Function Prototypes
//////////////////////////////////////////////////////////////////////////// */

int process_rc();	// Process the /etc/rc file
void err(char *);	// Spit a message to the terminal
void read_inittab();	// Read and parse the /etc/inittab file
void spawn(int);	// Spawn one /etc/inittab process

/* ////////////////////////////////////////////////////////////////////////////
			       Module Variables
//////////////////////////////////////////////////////////////////////////// */

struct initline inittab[NUMCMD];	// This table holds information about
					//  the processes spawned from
					//  /etc/inittab
int numcmd;				// Number of valid entries in inittab

/* ////////////////////////////////////////////////////////////////////////////
				    main()
///////////////////////////////////////////////////////////////////////////////
DESCRIPTION:	init's main()

REVISIONS:	200206201348 - RAC - Genesis
//////////////////////////////////////////////////////////////////////////// */

int main() {

    int		i;				// A local counter
    pid_t	pid;				// Local process ID variable

    process_rc();				// Go process /etc/rc script
    read_inittab();				// Go read /etc/inittab file
    for (i=0; i<numcmd; i++) {			// For each inittab line,
	spawn(i);				//  spawn the process
	}					// End 'for each inittab line'
    while (1) {					// Babysit the children forever
	pid = wait(NULL);			// Wait for a child to stop
	for (i=0; i<numcmd; i++) {		// For each child
	    if ((inittab[i].pid == pid) ||
		(inittab[i].pid == -1)) {	// This child is dead
		spawn(i);			// Now he is reborn
		}				// End 'this child is dead'
	    }					// End 'for each child'
	}					// End 'babysit forever'
    return 0;					// Should never get here
    }						// End main()

/* ////////////////////////////////////////////////////////////////////////////
				 process_rc()
///////////////////////////////////////////////////////////////////////////////
DESCRIPTION:	This function forks off a process to run the /etc/rc script.

REVISIONS:	200206201451 - RAC - Adapted from 2.0.38 simpleinit.c
//////////////////////////////////////////////////////////////////////////// */

int process_rc() {

    pid_t	pid;				// Process ID variable
    int		stat, st;			// Local temps

    pid = vfork();				// Do the fork
    if (pid == 0) {				// Child processing
	char *argv[2];				// Set up shell arguments here
	argv[0] = _PATH_BSHELL;			// Name of shell to run
	argv[1] = (char *)0;			// No more arguments
	close (0);				// Close stdin so the following
						//  call to open connects the
						//  input script to stdin
	if (open(_PATH_RC, O_RDONLY, 0) == 0) {	// Successful open
	    execv(_PATH_BSHELL, argv);		// Go run the script
	    err("exec of /etc/rc failed\n");	// Should never get here
	    _exit(2);				// Disaster!
	    }					// End 'successful open'
	err("open of /etc/rc failed\n");	// Open failure
	_exit(1);
	}					// End 'child processing'
    else if (pid > 0) {				// Parent processing
	while (wait(&stat) != pid) ;		// Wait for child to finish
	}					// End 'parent processing'
    else {					// Fork failure
	err("fork of /etc/rc failed\n");	// Tell the user
	}					// End 'fork failure'
    return WEXITSTATUS(stat);			// Return exit status
    }						// End process_rc()

/* ////////////////////////////////////////////////////////////////////////////
				read_inittab()
///////////////////////////////////////////////////////////////////////////////
DESCRIPTION:	This function reads the /etc/inittab file, parses each line,
		and fills in the 'inittab' table defined in this module.

REVISIONS:	200206201644 - RAC - Adapted from 2.0.38 simpleinit.c
//////////////////////////////////////////////////////////////////////////// */

void read_inittab() {

    FILE	*f;				// /etc/inittab file pointer
    int		i;				// A local counter
    char	buf[CMDSIZ];			// Put raw inittab lines here
    char	*ptr;				// A local temp

    if (!(f = fopen(_PATH_INITTAB, "r"))) {	// Open /etc/inittab, or die
	err("cannot open inittab\n");		//  in the attempt
	_exit(1);
	}					// End 'open error'

    numcmd = 0;					// No commands parsed yet
    while (1) {					// We'll break from this loop
	if ((numcmd >= NUMCMD-2) ||		// Quit when the table gets
	    (fgets(buf, CMDSIZ-1, f) == 0)) {	//  full or we read past the
	    break;				//  end of /etc/inittab
	    }					// End 'quit'
	buf[CMDSIZ-1] = 0;			// Make sure buf is terminated

	for (i=0; i<CMDSIZ; i++) {		// Ignore the first '#' on the
	    if (buf[i] == '#') {		//  line and anything after it
		buf[i] = 0;
		break;
		}				// End 'if'
	    }					// End 'for'

	if ((buf[0] == 0) ||			// Ignore empty lines
	    (buf[0] == '\n')) {
	    continue;
	    }					// End 'if'

    /*  Parse the line into its constituent fields */

	strcpy(inittab[numcmd].line, buf);

	strtok(inittab[numcmd].line, ":");
	strncpy(inittab[numcmd].tty, inittab[numcmd].line, 10);
	inittab[numcmd].tty[9] = 0;
	strncpy(inittab[numcmd].termcap, strtok((char *)0, ":"), 30);
	inittab[numcmd].termcap[29] = 0;

	ptr = strtok((char *)0, ":");
	strtok(ptr, " \t\n");
	inittab[numcmd].toks[0] = ptr;
	i = 1;
	while((ptr = strtok((char *)0, " \t\n"))) {
	    inittab[numcmd].toks[i++] = ptr;
	    }
	inittab[numcmd].toks[i] = (char *)0;

	numcmd++;				// Count line just processed
	}					// End 'while (1)'
    fclose(f);					// Close /etc/inittab
    }						// End read_inittab()

/* ////////////////////////////////////////////////////////////////////////////
				    spawn()
///////////////////////////////////////////////////////////////////////////////
DESCRIPTION:	This function spawns a process based on the information in the
		'inittab' table, which in turn came from the /etc/inittab file.

REVISIONS:	200206201800 - RAC - Adapted from 2.0.38 simpleinit.c
//////////////////////////////////////////////////////////////////////////// */

void spawn (int i) {

    pid_t	pid;
    int		j;
	
    pid = vfork();				// Create new process
    if (pid < 0) {				// Oops - didn't work
	inittab[i].pid = -1;			// Note failure in table
	err("fork failed\n");			// Inform the human
	}
    else if (pid) {				// Fork successful
	inittab[i].pid = pid;			// Parent puts new pid in table
	}
    else {					// Child execs new program
	char term[40];
	char *env[3];
		
	setsid();				// Create a new session ???
	for (j=0; j<getdtablesize(); j++) {	// Close all files
	    close(j);
	    }
	sprintf(term, "TERM=%s",		// Cook up the new environment
            inittab[i].termcap);
	env[0] = term;
	env[1] = (char *)0;
	env[2] = (char *)0;			// Is this needed?

	execve(inittab[i].toks[0],		// Fire off the program
            inittab[i].toks, env);
	err("exec failed\n");			// Should never get here ...
	sleep(5);				// ... or here ...
	_exit(1);				// ... or here
	}					// End 'child processing'
    }						// End spawn()

/* ////////////////////////////////////////////////////////////////////////////
				     err()
///////////////////////////////////////////////////////////////////////////////
DESCRIPTION:	A function to write a string to the console.

REVISIONS:	200206201519 - RAC - Copied from 2.0.38 simpleinit.c
//////////////////////////////////////////////////////////////////////////// */

void err(char *s) {

    int fd;					// A file descriptor

    fd = open("/dev/ttyS0", O_WRONLY);		// Open the serial port
    if (fd < 0) {				// Not much we can do if the
	return;					//  open fails
	}
    write(fd, "init: ", strlen("init: "));	// Identify message source
    write(fd, s, strlen(s));			// Emit message
    close(fd);					// Close the port
    }						// End err()
