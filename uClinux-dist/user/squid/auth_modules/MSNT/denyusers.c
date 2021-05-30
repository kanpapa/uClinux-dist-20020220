
/*
 * denyusers.c
 * (C) 2000 Antonino Iannella, Stellar-X Pty Ltd
 * Released under GPL, see COPYING-2.0 for details.
 * 
 * These routines are used to check if users attempting to authenticate
 * with Squid have a username which has been blocked by the system administrator.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include "sitedef.h"

#define NAMELEN     50		/* Maximum username length */

/* Global variables */

char *DeniedUsers;		/* Pointer to string of denied users */
off_t DenyUserSize;		/* Size of DENYUSER file */
struct stat FileBuf;		/* Stat data buffer */
time_t LastModTime;		/* Last DENYUSER file modification time */

/* Function declarations */

int Read_denyusers();
int Check_user(char *ConnectingUser);
void Checkforchange();

/*
 * Reads the DENYUSERS file for all users to be excluded.
 * Returns 0 if the user list was successfully loaded, and 1 in case of
 * error.
 * Logs any messages to the syslog daemon.
 */

int 
Read_denyusers()
{
    FILE *DFile;		/* DENYUSER file pointer */
    off_t DPos = 0;		/* File counter */
    char DChar;			/* Character buffer */

    /* Stat the file. If it does not exist, save the size as zero.
     * Clear the denied user string. Return. */

    if (stat(DENYUSERS, &FileBuf) == -1) {
	if (errno == ENOENT) {
	    LastModTime = (time_t) 0;
	    DenyUserSize = 0;
	    free(DeniedUsers);
	    DeniedUsers = malloc(sizeof(char));
	    DeniedUsers[0] = '\0';
	    return 0;
	} else {
	    syslog(LOG_USER | LOG_ERR, strerror(errno));
	    return 1;
	}
    }
    /* If it exists, save the modification time and size */
    LastModTime = FileBuf.st_mtime;
    DenyUserSize = FileBuf.st_size;

    /* Handle the special case of a zero length file */
    if (DenyUserSize == 0) {
	free(DeniedUsers);
	DeniedUsers = malloc(sizeof(char));
	DeniedUsers[0] = '\0';
	return 0;
    }
    /* Free and allocate space for a string to store the denied usernames */
    free(DeniedUsers);

    if ((DeniedUsers = malloc(sizeof(char) * (DenyUserSize + 1))) == NULL) {
	syslog(LOG_USER | LOG_ERR, "Read_denyusers: malloc(DeniedUsers) failed.");
	return 1;
    }
    /* Open the DENYUSERS file. Report any errors. */

    if ((DFile = fopen(DENYUSERS, "r")) == NULL) {
	syslog(LOG_USER | LOG_ERR, "Read_denyusers: Failed to open denied user file.");
	syslog(LOG_USER | LOG_ERR, strerror(errno));
	return 1;
    }
    /* Read user names into the DeniedUsers string */

    while (!feof(DFile)) {
	if ((DChar = fgetc(DFile)) == EOF)
	    break;
	else {
	    if (isspace(DChar))
		DeniedUsers[DPos++] = ' ';
	    else
		DeniedUsers[DPos++] = toupper(DChar);
	}
    }

    DeniedUsers[DPos] = '\0';
    fclose(DFile);
    return 0;
}

/*
 * Check to see if the username provided by Squid appears in the denied
 * user list.
 * Returns 0 if the user was not found, and 1 if they were.
 */

int 
Check_user(char *ConnectingUser)
{
    static char CUBuf[NAMELEN + 1];
    static int x;
    static char DenyMsg[256];

    /* If user string is empty, deny */
    if (ConnectingUser[0] == '\0')
	return 1;

    /* If denied user list is empty, allow */
    if (DenyUserSize == 0)
	return 0;

    /* Check if username string is found in the denied user list.
     * If so, deny. If not, allow. */

    sscanf(ConnectingUser, " %s ", CUBuf);

    for (x = 0; x <= strlen(CUBuf); x++)
	CUBuf[x] = toupper(CUBuf[x]);

    if (strstr(DeniedUsers, CUBuf) == NULL)
	return 0;
    else {
	sprintf(DenyMsg, "Denied access to user '%s'.", CUBuf);
	syslog(LOG_USER | LOG_ERR, DenyMsg);
	return 1;
    }
}

/*
 * Checks if there has been a change in the DENYUSERS file.
 * If the modification time has changed, then reload the denied user list.
 * This function is invoked at every SIGALRM signal, and at every SIGHUP
 * signal.
 */

void 
Checkforchange()
{
    struct stat ChkBuf;		/* Stat data buffer */

    /* Stat the DENYUSERS file. If it cannot be accessed, return. */

    if (stat(DENYUSERS, &ChkBuf) == -1) {
	if (errno == ENOENT) {
	    LastModTime = (time_t) 0;
	    DenyUserSize = 0;
	    free(DeniedUsers);
	    DeniedUsers = malloc(sizeof(char));
	    DeniedUsers[0] = '\0';
	    return;
	} else {
	    syslog(LOG_USER | LOG_ERR, strerror(errno));
	    return;
	}
    }
    /* If found, compare the modification time with the previously-recorded
     * modification time.
     * If the modification time has changed, reload the denied user list.
     * Log a message of its actions. */

    if (ChkBuf.st_mtime != LastModTime) {
	syslog(LOG_USER | LOG_INFO, "Checkforchange: Reloading denied user list.");
	Read_denyusers();
    }
}
