/*
 * tools.h
 */

#ifndef _TOOLS_H
#define _TOOLS_H

#ifdef __cplusplus
extern "C" {
#endif



/* 
 * General acros and constants.
 */
#ifdef WIN32
#  define SNMP_MAXPATH MAX_PATH
#else
#  ifdef PATH_MAX
#    define SNMP_MAXPATH PATH_MAX
#  else
#    define SNMP_MAXPATH MAXPATHLEN
#  endif
#endif

#define SNMP_MAXBUF		(1024 * 4)
#define SNMP_MAXBUF_MEDIUM	1024
#define SNMP_MAXBUF_SMALL	512

#define SNMP_MAXBUF_MESSAGE	1500

#define SNMP_MAXOID		64

#define SNMP_FILEMODE_CLOSED	0600
#define SNMP_FILEMODE_OPEN	0644

#define BYTESIZE(bitsize)       ((bitsize + 7) >> 3)
#define ROUNDUP8(x)		( ( (x+7) >> 3 ) * 8 )



#define SNMP_FREE(s)		if (s) { free((void *)s); s=NULL; }

					/* XXX Not optimal everywhere. */
#define SNMP_MALLOC_STRUCT(s)   (struct s *) calloc(1, sizeof(struct s))
#define SNMP_ZERO(s,l)		if (s) memset(s, 0, l);


#define TOUPPER(c)	(c >= 'a' && c <= 'z' ? c - ('a' - 'A') : c)
#define TOLOWER(c)	(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c)

#define HEX2VAL(s) \
	((isalpha(s) ? (TOLOWER(s)-'a'+10) : (TOLOWER(s)-'0')) & 0xf)
#define VAL2HEX(s)	( (s) + (((s) >= 10) ? ('a'-10) : '0') )


#define SNMP_MAX(a,b) ((a) > (b) ? (a) : (b))
#define SNMP_MIN(a,b) ((a) > (b) ? (b) : (a))

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE  1
#endif

/*
 * QUIT the FUNction:
 *	e	Error code variable
 *	l	Label to goto to cleanup and get out of the function.
 *
 * XXX	It would be nice if the label could be constructed by the
 *	preprocessor in context.  Limited to a single error return value.
 *	Temporary hack at best.
 */
#define QUITFUN(e, l)			\
	if ( (e) != SNMPERR_SUCCESS) {	\
		rval = SNMPERR_GENERR;	\
		goto l ;		\
	}

/*
 * DIFFTIMEVAL
 *	Set <diff> to the difference between <now> (current) and <then> (past).
 *
 * ASSUMES that all inputs are (struct timeval)'s.
 * Cf. system.c:calculate_time_diff().
 */
#define DIFFTIMEVAL(now, then, diff) 			\
{							\
	now.tv_sec--;					\
	now.tv_usec += 1000000L;			\
	diff.tv_sec  = now.tv_sec  - then.tv_sec;	\
	diff.tv_usec = now.tv_usec - then.tv_usec;	\
	if (diff.tv_usec > 1000000L){			\
		diff.tv_usec -= 1000000L;		\
		diff.tv_sec++;				\
	}						\
}


/*
 * ISTRANSFORM
 * ASSUMES the minimum length for ttype and toid.
 */
#define USM_LENGTH_OID_TRANSFORM	10

#define ISTRANSFORM(ttype, toid)					\
	!snmp_oid_compare(ttype, USM_LENGTH_OID_TRANSFORM,		\
		usm ## toid ## Protocol, USM_LENGTH_OID_TRANSFORM)

#define ENGINETIME_MAX	2147483647	/* ((2^31)-1) */
#define ENGINEBOOT_MAX	2147483647	/* ((2^31)-1) */




/* 
 * Prototypes.
 */
void	free_zero (void *buf, size_t size);

u_char *malloc_random (size_t *size);
u_char *malloc_zero (size_t size);
int     memdup (u_char **to, const u_char *from, size_t size);

u_int	binary_to_hex (const u_char *input, size_t len, char **output);
int	hex_to_binary2 (const u_char *input, size_t len, char **output);

void	dump_chunk (const char *debugtoken, const char *title, const u_char *buf, int size);
char   *dump_snmpEngineID (const u_char *buf, size_t *buflen);

typedef void * marker_t;
marker_t atime_newMarker(void);
void atime_setMarker(marker_t pm);
int atime_ready( marker_t pm, int deltaT);

#ifdef __cplusplus
}
#endif

#endif /* _TOOLS_H */
