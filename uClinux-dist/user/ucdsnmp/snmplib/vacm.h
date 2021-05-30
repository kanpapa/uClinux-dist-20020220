/*
 * vacm.h
 *
 * SNMPv3 View-based Access Control Model
 */

#ifndef VACM_H
#define VACM_H

#ifdef __cplusplus
extern "C" {
#endif

#define SECURITYMODEL	1
#define SECURITYNAME	2
#define SECURITYGROUP	3
#define SECURITYSTORAGE	4
#define SECURITYSTATUS	5

#define ACCESSPREFIX	1
#define ACCESSMODEL	2
#define ACCESSLEVEL	3
#define ACCESSMATCH	4
#define ACCESSREAD	5
#define ACCESSWRITE	6
#define ACCESSNOTIFY	7
#define ACCESSSTORAGE	8
#define ACCESSSTATUS	9

#define VIEWNAME	1
#define VIEWSUBTREE	2
#define VIEWMASK	3
#define VIEWTYPE	4
#define VIEWSTORAGE	5
#define VIEWSTATUS	6

#define VACM_MAX_STRING 32
#define VACMSTRINGLEN   34  /* VACM_MAX_STRING + 2 */

struct vacm_securityEntry {
    char	securityName[VACMSTRINGLEN];
    snmp_ipaddr	sourceIp;
    snmp_ipaddr	sourceMask;
    char	community[VACMSTRINGLEN];
    struct vacm_securityEntry *next;
};

struct vacm_groupEntry {
    int		securityModel;
    char	securityName[VACMSTRINGLEN];
    char	groupName[VACMSTRINGLEN];
    int		storageType;
    int		status;

    u_long	bitMask;
    struct vacm_groupEntry *reserved;
    struct vacm_groupEntry *next;
};

struct vacm_accessEntry {
    char	groupName[VACMSTRINGLEN];
    char	contextPrefix[VACMSTRINGLEN];
    int		securityModel;
    int		securityLevel;
    int 	contextMatch;
    char	readView[VACMSTRINGLEN];
    char	writeView[VACMSTRINGLEN];
    char	notifyView[VACMSTRINGLEN];
    int		storageType;
    int		status;

    u_long	bitMask;
    struct vacm_accessEntry *reserved;
    struct vacm_accessEntry *next;
};

struct vacm_viewEntry {
    char	viewName[VACMSTRINGLEN];
    oid		viewSubtree[MAX_OID_LEN];
    size_t	viewSubtreeLen;
    u_char	viewMask[VACMSTRINGLEN];
    size_t	viewMaskLen;
    int		viewType;
    int		viewStorageType;
    int		viewStatus;

    u_long	bitMask;

    struct vacm_viewEntry *reserved;
    struct vacm_viewEntry *next;
};

void vacm_destroyViewEntry (const char *, oid *, size_t);
void vacm_destroyAllViewEntries (void);

struct vacm_viewEntry *
vacm_getViewEntry (const char *, oid *, size_t);
/*
 * Returns a pointer to the viewEntry with the
 * same viewName and viewSubtree
 * Returns NULL if that entry does not exist.
 */

void
vacm_scanViewInit (void);
/*
 * Initialized the scan routines so that they will begin at the
 * beginning of the list of viewEntries.
 *
 */


struct vacm_viewEntry *
vacm_scanViewNext (void);
/*
 * Returns a pointer to the next viewEntry.
 * These entries are returned in no particular order,
 * but if N entries exist, N calls to view_scanNext() will
 * return all N entries once.
 * Returns NULL if all entries have been returned.
 * view_scanInit() starts the scan over.
 */

struct vacm_viewEntry *
vacm_createViewEntry (const char *, oid *, size_t);
/*
 * Creates a viewEntry with the given index
 * and returns a pointer to it.
 * The status of this entry is created as invalid.
 */

void vacm_destroyGroupEntry (int, const char *);
void vacm_destroyAllGroupEntries (void);
struct vacm_groupEntry *vacm_createGroupEntry (int, const char *);
struct vacm_groupEntry *vacm_getGroupEntry (int, const char *);
void vacm_scanGroupInit (void);
struct vacm_groupEntry *vacm_scanGroupNext (void);

void vacm_destroyAccessEntry (const char *, const char *, int, int);
void vacm_destroyAllAccessEntries (void);
struct vacm_accessEntry *vacm_createAccessEntry (const char *, const char *, int, int);
struct vacm_accessEntry *vacm_getAccessEntry (const char *, const char *, int, int);
void vacm_scanAccessInit (void);
struct vacm_accessEntry *vacm_scanAccessNext (void);

void vacm_destroySecurityEntry (const char *);
struct vacm_securityEntry *vacm_createSecurityEntry (const char *);
struct vacm_securityEntry *vacm_getSecurityEntry (const char *);
void vacm_scanSecurityInit (void);
struct vacm_securityEntry *vacm_scanSecurityEntry (void);
int vacm_is_configured(void);

#ifdef __cplusplus
}
#endif

#endif /* VACM_H */
