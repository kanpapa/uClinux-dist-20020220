
/*
 * $Id: protos.h,v 1.340.2.28 2000/04/07 20:32:30 wessels Exp $
 *
 *
 * SQUID Internet Object Cache  http://squid.nlanr.net/Squid/
 * ----------------------------------------------------------
 *
 *  Squid is the result of efforts by numerous individuals from the
 *  Internet community.  Development is led by Duane Wessels of the
 *  National Laboratory for Applied Network Research and funded by the
 *  National Science Foundation.  Squid is Copyrighted (C) 1998 by
 *  the Regents of the University of California.  Please see the
 *  COPYRIGHT file for full details.  Squid incorporates software
 *  developed and/or copyrighted by other sources.  Please see the
 *  CREDITS file for full details.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
 *
 */

extern void accessLogLog(AccessLogEntry *);
extern void accessLogRotate(void);
extern void accessLogClose(void);
extern void accessLogInit(void);
extern const char *accessLogTime(time_t);
extern void hierarchyNote(HierarchyLogEntry *, hier_code, const char *);
#if FORW_VIA_DB
extern void fvdbCountVia(const char *key);
extern void fvdbCountForw(const char *key);
#endif

extern aclCheck_t *aclChecklistCreate(const struct _acl_access *,
    request_t *,
    const char *ident);
extern void aclNBCheck(aclCheck_t *, PF *, void *);
extern int aclCheckFast(const struct _acl_access *A, aclCheck_t *);
extern void aclChecklistFree(aclCheck_t *);
extern int aclMatchAclList(const acl_list * list, aclCheck_t * checklist);
extern void aclDestroyAccessList(struct _acl_access **list);
extern void aclDestroyAcls(acl **);
extern void aclParseAccessLine(struct _acl_access **);
extern void aclParseAclLine(acl **);
extern int aclIsProxyAuth(const char *name);
extern int aclGetDenyInfoPage(acl_deny_info_list ** head, const char *name);
extern void aclParseDenyInfoLine(struct _acl_deny_info_list **);
extern void aclDestroyDenyInfoList(struct _acl_deny_info_list **);
extern void aclDestroyRegexList(struct _relist *data);
extern int aclMatchRegex(relist * data, const char *word);
extern void aclParseRegexList(void *curlist);
extern const char *aclTypeToStr(squid_acl);
extern wordlist *aclDumpGeneric(const acl *);
extern int aclPurgeMethodInUse(acl_access *);

#if USE_ASYNC_IO
extern int aio_cancel(aio_result_t *);
extern int aio_open(const char *, int, mode_t, aio_result_t *);
extern int aio_read(int, char *, int, off_t, int, aio_result_t *);
extern int aio_write(int, char *, int, off_t, int, aio_result_t *);
extern int aio_close(int, aio_result_t *);
extern int aio_stat(const char *, struct stat *, aio_result_t *);
extern int aio_unlink(const char *, aio_result_t *);
extern int aio_opendir(const char *, aio_result_t *);
extern aio_result_t *aio_poll_done(void);
extern int aio_operations_pending(void);
extern int aio_overloaded(void);
extern int aio_sync(void);
extern int aio_get_queue_len(void);

extern void aioInit(void);
extern void aioCancel(int);
extern void aioOpen(const char *, int, mode_t, AIOCB *, void *);
extern void aioClose(int);
extern void aioWrite(int, int offset, char *, int size, AIOCB *, void *, FREE *);
extern void aioRead(int, int offset, char *, int size, AIOCB *, void *);
extern void aioStat(char *, struct stat *, AIOCB *, void *);
extern void aioUnlink(const char *, AIOCB *, void *);
extern void aioCheckCallbacks(void);
extern void aioSync(void);
extern int aioQueueSize(void);
#endif

/*
 * cache_cf.c
 */
extern int parseConfigFile(const char *file_name);
extern void intlistDestroy(intlist **);
extern int intlistFind(intlist * list, int i);
extern wordlist *wordlistAdd(wordlist **, const char *);
extern wordlist *wordlistDup(const wordlist *);
extern void wordlistDestroy(wordlist **);
extern void configFreeMemory(void);
extern void wordlistCat(const wordlist *, MemBuf * mb);
extern void allocate_new_swapdir(cacheSwap *);
extern void self_destruct(void);
extern int GetInteger(void);


extern void cbdataInit(void);
#if CBDATA_DEBUG
extern void cbdataAddDbg(const void *p, CBDUNL *, int, const char *, int);
#else
extern void cbdataAdd(const void *p, CBDUNL *, int);
#endif
extern void cbdataFree(void *p);
extern void cbdataLock(const void *p);
extern void cbdataUnlock(const void *p);
extern int cbdataValid(const void *p);
extern CBDUNL cbdataXfree;

extern void clientdbInit(void);
extern void clientdbUpdate(struct in_addr, log_type, protocol_t, size_t);
extern int clientdbCutoffDenied(struct in_addr);
extern void clientdbDump(StoreEntry *);
extern void clientdbFreeMemory(void);
extern int clientdbEstablished(struct in_addr, int);

extern void clientAccessCheck(void *);
extern void clientAccessCheckDone(int, void *);
extern int modifiedSince(StoreEntry *, request_t *);
extern char *clientConstructTraceEcho(clientHttpRequest *);
extern void clientPurgeRequest(clientHttpRequest *);
extern int checkNegativeHit(StoreEntry *);
extern void clientHttpConnectionsOpen(void);
extern void clientHttpConnectionsClose(void);
extern StoreEntry *clientCreateStoreEntry(clientHttpRequest *, method_t, request_flags);
extern int isTcpHit(log_type);

extern int commSetNonBlocking(int fd);
extern int commUnsetNonBlocking(int fd);
extern void commSetCloseOnExec(int fd);
extern int comm_accept(int fd, struct sockaddr_in *, struct sockaddr_in *);
extern void comm_close(int fd);
#if LINGERING_CLOSE
extern void comm_lingering_close(int fd);
#endif
extern void commConnectStart(int fd, const char *, u_short, CNCB *, void *);
extern int comm_connect_addr(int sock, const struct sockaddr_in *);
extern void comm_init(void);
extern int comm_listen(int sock);
extern int comm_open(int, int, struct in_addr, u_short port, int, const char *note);
extern u_short comm_local_port(int fd);

extern void commSetSelect(int, unsigned int, PF *, void *, time_t);
extern void comm_add_close_handler(int fd, PF *, void *);
extern void comm_remove_close_handler(int fd, PF *, void *);
extern int comm_udp_sendto(int, const struct sockaddr_in *, int, const void *, int);
extern void comm_write(int fd,
    char *buf,
    int size,
    CWCB * handler,
    void *handler_data,
    FREE *);
extern void comm_write_mbuf(int fd, MemBuf mb, CWCB * handler, void *handler_data);
extern void commCallCloseHandlers(int fd);
extern int commSetTimeout(int fd, int, PF *, void *);
extern void commSetDefer(int fd, DEFER * func, void *);
extern int ignoreErrno(int);
extern void commCloseAllSockets(void);


/*
 * comm_select.c
 */
extern void comm_select_init(void);
#if HAVE_POLL
extern int comm_poll(int);
#else
extern int comm_select(int);
#endif
extern void commUpdateReadBits(int, PF *);
extern void commUpdateWriteBits(int, PF *);

extern void packerToStoreInit(Packer * p, StoreEntry * e);
extern void packerToMemInit(Packer * p, MemBuf * mb);
extern void packerClean(Packer * p);
extern void packerAppend(Packer * p, const char *buf, int size);
#if STDC_HEADERS
extern void packerPrintf(Packer * p, const char *fmt,...);
#else
extern void packerPrintf();
#endif


/* see debug.c for info on context-based debugging */
extern Ctx ctx_enter(const char *descr);
extern void ctx_exit(Ctx ctx);

extern void _db_init(const char *logfile, const char *options);
extern void _db_rotate_log(void);

#if STDC_HEADERS
extern void _db_print(const char *,...);
#else
extern void _db_print();
#endif
extern void xassert(const char *, const char *, int);

/* packs, then prints an object using debug() */
extern void debugObj(int section, int level, const char *label, void *obj, ObjPackMethod pm);


extern int file_open(const char *path, int mode);
extern void file_close(int fd);
extern void file_write(int, off_t, void *, int len, DWCB *, void *, FREE *);
extern void file_write_mbuf(int fd, off_t, MemBuf mb, DWCB * handler, void *handler_data);
extern void file_read(int, char *, int, off_t, DRCB *, void *);
extern void disk_init(void);

extern void dnsShutdown(void);
extern void dnsInit(void);
extern void dnsSubmit(const char *lookup, HLPCB * callback, void *data);

/* dns_internal.c */
extern void idnsInit(void);
extern void idnsShutdown(void);
extern void idnsALookup(const char *, IDNSCB *, void *);
extern void idnsPTRLookup(const struct in_addr, IDNSCB *, void *);

extern void eventAdd(const char *name, EVH * func, void *arg, double when, int);
extern void eventAddIsh(const char *name, EVH * func, void *arg, double delta_ish, int);
extern void eventRun(void);
extern time_t eventNextTime(void);
extern void eventDelete(EVH * func, void *arg);
extern void eventInit(void);
extern void eventFreeMemory(void);
extern int eventFind(EVH *, void *);

extern void fd_close(int fd);
extern void fd_open(int fd, unsigned int type, const char *);
extern void fd_note(int fd, const char *);
extern void fd_bytes(int fd, int len, unsigned int type);
extern void fdFreeMemory(void);
extern void fdDumpOpen(void);
extern int fdNFree(void);
extern void fdAdjustReserved(void);

extern fileMap *file_map_create(void);
extern int file_map_allocate(fileMap *, int);
extern int file_map_bit_set(fileMap *, int);
extern int file_map_bit_test(fileMap *, int);
extern void file_map_bit_reset(fileMap *, int);
extern void filemapFreeMemory(fileMap *);


extern void fqdncache_nbgethostbyaddr(struct in_addr, FQDNH *, void *);
extern int fqdncacheUnregister(struct in_addr, void *);
extern const char *fqdncache_gethostbyaddr(struct in_addr, int flags);
extern void fqdncache_init(void);
extern void fqdnStats(StoreEntry *);
extern void fqdncacheReleaseInvalid(const char *);
extern const char *fqdnFromAddr(struct in_addr);
extern int fqdncacheQueueDrain(void);
extern void fqdncacheFreeMemory(void);
extern void fqdncache_restart(void);
extern EVH fqdncache_purgelru;

extern void ftpStart(FwdState *);
extern char *ftpUrlWith2f(const request_t *);

extern void gopherStart(FwdState *);
extern int gopherCachable(const char *);


extern void whoisStart(FwdState *);

extern int httpCachable(method_t);
extern void httpStart(FwdState *);
extern void httpParseReplyHeaders(const char *, http_reply *);
extern void httpProcessReplyHeader(HttpStateData *, const char *, int);
extern mb_size_t httpBuildRequestPrefix(request_t * request,
    request_t * orig_request,
    StoreEntry * entry,
    MemBuf * mb,
    int cfd,
    http_state_flags);
extern void httpAnonInitModule(void);
extern int httpAnonHdrAllowed(http_hdr_type hdr_id);
extern int httpAnonHdrDenied(http_hdr_type hdr_id);
extern void httpBuildRequestHeader(request_t *, request_t *, StoreEntry *, HttpHeader *, int, http_state_flags);

/* ETag */
extern int etagParseInit(ETag * etag, const char *str);
extern int etagIsEqual(const ETag * tag1, const ETag * tag2);

/* Http Status Line */
/* init/clean */
extern void httpStatusLineInit(HttpStatusLine * sline);
extern void httpStatusLineClean(HttpStatusLine * sline);
/* set/get values */
extern void httpStatusLineSet(HttpStatusLine * sline, double version,
    http_status status, const char *reason);
extern const char *httpStatusLineReason(const HttpStatusLine * sline);
/* parse/pack */
/* parse a 0-terminating buffer and fill internal structires; returns true on success */
extern int httpStatusLineParse(HttpStatusLine * sline, const char *start,
    const char *end);
/* pack fields using Packer */
extern void httpStatusLinePackInto(const HttpStatusLine * sline, Packer * p);
extern const char *httpStatusString(http_status status);

/* Http Body */
/* init/clean */
extern void httpBodyInit(HttpBody * body);
extern void httpBodyClean(HttpBody * body);
/* get body ptr (always use this) */
extern const char *httpBodyPtr(const HttpBody * body);
/* set body, does not clone mb so you should not reuse it */
extern void httpBodySet(HttpBody * body, MemBuf * mb);

/* pack */
extern void httpBodyPackInto(const HttpBody * body, Packer * p);

/* Http Cache Control Header Field */
extern void httpHdrCcInitModule(void);
extern void httpHdrCcCleanModule(void);
extern HttpHdrCc *httpHdrCcCreate(void);
extern HttpHdrCc *httpHdrCcParseCreate(const String * str);
extern void httpHdrCcDestroy(HttpHdrCc * cc);
extern HttpHdrCc *httpHdrCcDup(const HttpHdrCc * cc);
extern void httpHdrCcPackInto(const HttpHdrCc * cc, Packer * p);
extern void httpHdrCcJoinWith(HttpHdrCc * cc, const HttpHdrCc * new_cc);
extern void httpHdrCcSetMaxAge(HttpHdrCc * cc, int max_age);
extern void httpHdrCcSetSMaxAge(HttpHdrCc * cc, int s_maxage);
extern void httpHdrCcUpdateStats(const HttpHdrCc * cc, StatHist * hist);
extern void httpHdrCcStatDumper(StoreEntry * sentry, int idx, double val, double size, int count);

/* Http Range Header Field */
extern HttpHdrRange *httpHdrRangeParseCreate(const String * range_spec);
/* returns true if ranges are valid; inits HttpHdrRange */
extern int httpHdrRangeParseInit(HttpHdrRange * range, const String * range_spec);
extern void httpHdrRangeDestroy(HttpHdrRange * range);
extern HttpHdrRange *httpHdrRangeDup(const HttpHdrRange * range);
extern void httpHdrRangePackInto(const HttpHdrRange * range, Packer * p);
/* iterate through specs */
extern HttpHdrRangeSpec *httpHdrRangeGetSpec(const HttpHdrRange * range, HttpHdrRangePos * pos);
/* adjust specs after the length is known */
extern int httpHdrRangeCanonize(HttpHdrRange *, ssize_t);
/* other */
extern String httpHdrRangeBoundaryStr(clientHttpRequest * http);
extern int httpHdrRangeIsComplex(const HttpHdrRange * range);
extern int httpHdrRangeWillBeComplex(const HttpHdrRange * range);
extern ssize_t httpHdrRangeFirstOffset(const HttpHdrRange * range);
extern ssize_t httpHdrRangeLowestOffset(const HttpHdrRange * range, ssize_t);


/* Http Content Range Header Field */
extern HttpHdrContRange *httpHdrContRangeCreate(void);
extern HttpHdrContRange *httpHdrContRangeParseCreate(const char *crange_spec);
/* returns true if range is valid; inits HttpHdrContRange */
extern int httpHdrContRangeParseInit(HttpHdrContRange * crange, const char *crange_spec);
extern void httpHdrContRangeDestroy(HttpHdrContRange * crange);
extern HttpHdrContRange *httpHdrContRangeDup(const HttpHdrContRange * crange);
extern void httpHdrContRangePackInto(const HttpHdrContRange * crange, Packer * p);
/* inits with given spec */
extern void httpHdrContRangeSet(HttpHdrContRange *, HttpHdrRangeSpec, ssize_t);

/* Http Header Tools */
extern HttpHeaderFieldInfo *httpHeaderBuildFieldsInfo(const HttpHeaderFieldAttrs * attrs, int count);
extern void httpHeaderDestroyFieldsInfo(HttpHeaderFieldInfo * info, int count);
extern int httpHeaderIdByName(const char *name, int name_len, const HttpHeaderFieldInfo * attrs, int end);
extern int httpHeaderIdByNameDef(const char *name, int name_len);
extern const char *httpHeaderNameById(int id);
extern void httpHeaderMaskInit(HttpHeaderMask * mask, int value);
extern void httpHeaderCalcMask(HttpHeaderMask * mask, const int *enums, int count);
extern int httpHeaderHasConnDir(const HttpHeader * hdr, const char *directive);
extern void httpHeaderAddContRange(HttpHeader *, HttpHdrRangeSpec, ssize_t);
extern void strListAdd(String * str, const char *item, char del);
extern int strListIsMember(const String * str, const char *item, char del);
extern int strListIsSubstr(const String * list, const char *s, char del);
extern int strListGetItem(const String * str, char del, const char **item, int *ilen, const char **pos);
extern const char *getStringPrefix(const char *str, const char *end);
extern int httpHeaderParseInt(const char *start, int *val);
extern int httpHeaderParseSize(const char *start, ssize_t * sz);
extern int httpHeaderReset(HttpHeader * hdr);
#if STDC_HEADERS
extern void httpHeaderPutStrf(HttpHeader * hdr, http_hdr_type id, const char *fmt,...);
#else
extern void httpHeaderPutStrf();
#endif


/* Http Header */
extern void httpHeaderInitModule(void);
extern void httpHeaderCleanModule(void);
/* init/clean */
extern void httpHeaderInit(HttpHeader * hdr, http_hdr_owner_type owner);
extern void httpHeaderClean(HttpHeader * hdr);
/* append/update */
extern void httpHeaderAppend(HttpHeader * dest, const HttpHeader * src);
extern void httpHeaderUpdate(HttpHeader * old, const HttpHeader * fresh, const HttpHeaderMask * denied_mask);
/* parse/pack */
extern int httpHeaderParse(HttpHeader * hdr, const char *header_start, const char *header_end);
extern void httpHeaderPackInto(const HttpHeader * hdr, Packer * p);
/* field manipulation */
extern int httpHeaderHas(const HttpHeader * hdr, http_hdr_type type);
extern void httpHeaderPutInt(HttpHeader * hdr, http_hdr_type type, int number);
extern void httpHeaderPutTime(HttpHeader * hdr, http_hdr_type type, time_t time);
extern void httpHeaderPutStr(HttpHeader * hdr, http_hdr_type type, const char *str);
extern void httpHeaderPutAuth(HttpHeader * hdr, const char *authScheme, const char *realm);
extern void httpHeaderPutCc(HttpHeader * hdr, const HttpHdrCc * cc);
extern void httpHeaderPutContRange(HttpHeader * hdr, const HttpHdrContRange * cr);
extern void httpHeaderPutRange(HttpHeader * hdr, const HttpHdrRange * range);
extern void httpHeaderPutExt(HttpHeader * hdr, const char *name, const char *value);
extern int httpHeaderGetInt(const HttpHeader * hdr, http_hdr_type id);
extern time_t httpHeaderGetTime(const HttpHeader * hdr, http_hdr_type id);
extern TimeOrTag httpHeaderGetTimeOrTag(const HttpHeader * hdr, http_hdr_type id);
extern HttpHdrCc *httpHeaderGetCc(const HttpHeader * hdr);
extern ETag httpHeaderGetETag(const HttpHeader * hdr, http_hdr_type id);
extern HttpHdrRange *httpHeaderGetRange(const HttpHeader * hdr);
extern HttpHdrContRange *httpHeaderGetContRange(const HttpHeader * hdr);
extern const char *httpHeaderGetStr(const HttpHeader * hdr, http_hdr_type id);
extern const char *httpHeaderGetLastStr(const HttpHeader * hdr, http_hdr_type id);
extern const char *httpHeaderGetAuth(const HttpHeader * hdr, http_hdr_type id, const char *authScheme);
extern String httpHeaderGetList(const HttpHeader * hdr, http_hdr_type id);
extern int httpHeaderDelByName(HttpHeader * hdr, const char *name);
extern int httpHeaderDelById(HttpHeader * hdr, http_hdr_type id);
extern void httpHeaderDelAt(HttpHeader * hdr, HttpHeaderPos pos);
/* avoid using these low level routines */
extern HttpHeaderEntry *httpHeaderGetEntry(const HttpHeader * hdr, HttpHeaderPos * pos);
extern HttpHeaderEntry *httpHeaderFindEntry(const HttpHeader * hdr, http_hdr_type id);
extern void httpHeaderAddEntry(HttpHeader * hdr, HttpHeaderEntry * e);
extern HttpHeaderEntry *httpHeaderEntryClone(const HttpHeaderEntry * e);
extern void httpHeaderEntryPackInto(const HttpHeaderEntry * e, Packer * p);
/* store report about current header usage and other stats */
extern void httpHeaderStoreReport(StoreEntry * e);

/* Http Msg (currently in HttpReply.c @?@ ) */
extern int httpMsgIsPersistent(float http_ver, const HttpHeader * hdr);
extern int httpMsgIsolateHeaders(const char **parse_start, const char **blk_start, const char **blk_end);

/* Http Reply */
extern void httpReplyInitModule(void);
/* create/destroy */
extern HttpReply *httpReplyCreate(void);
extern void httpReplyDestroy(HttpReply * rep);
/* reset: clean, then init */
extern void httpReplyReset(HttpReply * rep);
/* absorb: copy the contents of a new reply to the old one, destroy new one */
extern void httpReplyAbsorb(HttpReply * rep, HttpReply * new_rep);
/* parse returns -1,0,+1 on error,need-more-data,success */
extern int httpReplyParse(HttpReply * rep, const char *buf, ssize_t);
extern void httpReplyPackInto(const HttpReply * rep, Packer * p);
/* ez-routines */
/* mem-pack: returns a ready to use mem buffer with a packed reply */
extern MemBuf httpReplyPack(const HttpReply * rep);
/* swap: create swap-based packer, pack, destroy packer */
extern void httpReplySwapOut(const HttpReply * rep, StoreEntry * e);
/* set commonly used info with one call */
extern void httpReplySetHeaders(HttpReply * rep, double ver, http_status status,
    const char *reason, const char *ctype, int clen, time_t lmt, time_t expires);
/* do everything in one call: init, set, pack, clean, return MemBuf */
extern MemBuf httpPackedReply(double ver, http_status status, const char *ctype,
    int clen, time_t lmt, time_t expires);
/* construct 304 reply and pack it into MemBuf, return MemBuf */
extern MemBuf httpPacked304Reply(const HttpReply * rep);
/* update when 304 reply is received for a cached object */
extern void httpReplyUpdateOnNotModified(HttpReply * rep, HttpReply * freshRep);
/* header manipulation */
extern int httpReplyContentLen(const HttpReply * rep);
extern const char *httpReplyContentType(const HttpReply * rep);
extern time_t httpReplyExpires(const HttpReply * rep);
extern int httpReplyHasCc(const HttpReply * rep, http_hdr_cc_type type);
extern void httpRedirectReply(HttpReply *, http_status, const char *);
extern int httpReplyBodySize(method_t, HttpReply *);

/* Http Request */
extern request_t *requestCreate(method_t, protocol_t, const char *urlpath);
extern void requestDestroy(request_t *);
extern request_t *requestLink(request_t *);
extern void requestUnlink(request_t *);
extern int httpRequestParseHeader(request_t * req, const char *parse_start);
extern void httpRequestSwapOut(const request_t * req, StoreEntry * e);
extern void httpRequestPack(const request_t * req, Packer * p);
extern int httpRequestPrefixLen(const request_t * req);
extern int httpRequestHdrAllowed(const HttpHeaderEntry * e, String * strConnection);
extern int httpRequestHdrAllowedByName(http_hdr_type id);

extern void icmpOpen(void);
extern void icmpClose(void);
extern void icmpPing(struct in_addr to);
extern void icmpSourcePing(struct in_addr to, const icp_common_t *, const char *url);
extern void icmpDomainPing(struct in_addr to, const char *domain);

extern void *icpCreateMessage(icp_opcode opcode,
    int flags,
    const char *url,
    int reqnum,
    int pad);
extern int icpUdpSend(int, const struct sockaddr_in *, icp_common_t *, log_type, int);
extern PF icpHandleUdp;
extern PF icpUdpSendQueue;
extern PF httpAccept;

#ifdef SQUID_SNMP
extern PF snmpHandleUdp;
extern void snmpInit(void);
extern void snmpConnectionOpen(void);
extern void snmpConnectionShutdown(void);
extern void snmpConnectionClose(void);
extern void snmpDebugOid(int lvl, oid * Name, snint Len);
extern void addr2oid(struct in_addr addr, oid * Dest);
extern struct in_addr *oid2addr(oid * id);
extern struct in_addr *client_entry(struct in_addr *current);
extern variable_list *snmp_basicFn(variable_list *, snint *);
extern variable_list *snmp_confFn(variable_list *, snint *);
extern variable_list *snmp_sysFn(variable_list *, snint *);
extern variable_list *snmp_prfSysFn(variable_list *, snint *);
extern variable_list *snmp_prfProtoFn(variable_list *, snint *);
extern variable_list *snmp_prfPeerFn(variable_list *, snint *);
extern variable_list *snmp_netIpFn(variable_list *, snint *);
extern variable_list *snmp_netFqdnFn(variable_list *, snint *);
extern variable_list *snmp_netDnsFn(variable_list *, snint *);
extern variable_list *snmp_meshPtblFn(variable_list *, snint *);
extern variable_list *snmp_meshCtblFn(variable_list *, snint *);
#endif /* SQUID_SNMP */

#if USE_WCCP
extern void wccpInit(void);
extern void wccpConnectionOpen(void);
extern void wccpConnectionShutdown(void);
extern void wccpConnectionClose(void);
#endif /* USE_WCCP */

extern void icpHandleIcpV3(int, struct sockaddr_in, char *, int);
extern int icpCheckUdpHit(StoreEntry *, request_t * request);
extern void icpConnectionsOpen(void);
extern void icpConnectionShutdown(void);
extern void icpConnectionClose(void);
extern int icpSetCacheKey(const cache_key * key);
extern const cache_key *icpGetCacheKey(const char *url, int reqnum);

extern void ipcache_nbgethostbyname(const char *name,
    IPH * handler,
    void *handlerData);
extern EVH ipcache_purgelru;
extern const ipcache_addrs *ipcache_gethostbyname(const char *, int flags);
extern void ipcacheInvalidate(const char *);
extern void ipcacheReleaseInvalid(const char *);
extern void ipcache_init(void);
extern void stat_ipcache_get(StoreEntry *);
extern int ipcacheQueueDrain(void);
extern void ipcacheCycleAddr(const char *name, ipcache_addrs *);
extern void ipcacheMarkBadAddr(const char *name, struct in_addr);
extern void ipcacheMarkGoodAddr(const char *name, struct in_addr);
extern void ipcacheFreeMemory(void);
extern ipcache_addrs *ipcacheCheckNumeric(const char *name);
extern void ipcache_restart(void);
extern int ipcacheUnregister(const char *name, void *data);

/* MemBuf */
/* init with specific sizes */
extern void memBufInit(MemBuf * mb, mb_size_t szInit, mb_size_t szMax);
/* init with defaults */
extern void memBufDefInit(MemBuf * mb);
/* cleans mb; last function to call if you do not give .buf away */
extern void memBufClean(MemBuf * mb);
/* resets mb preserving (or initializing if needed) memory buffer */
extern void memBufReset(MemBuf * mb);
/* unfirtunate hack to test if the buffer has been Init()ialized */
extern int memBufIsNull(MemBuf * mb);
/* calls memcpy, appends exactly size bytes, extends buffer if needed */
extern void memBufAppend(MemBuf * mb, const char *buf, mb_size_t size);
/* calls snprintf, extends buffer if needed */
#if STDC_HEADERS
extern void memBufPrintf(MemBuf * mb, const char *fmt,...);
#else
extern void memBufPrintf();
#endif
/* vprintf for other printf()'s to use */
extern void memBufVPrintf(MemBuf * mb, const char *fmt, va_list ap);
/* returns free() function to be used, _freezes_ the object! */
extern FREE *memBufFreeFunc(MemBuf * mb);
/* puts report on MemBuf _module_ usage into mb */
extern void memBufReport(MemBuf * mb);

extern char *mime_get_header(const char *mime, const char *header);
extern char *mime_get_header_field(const char *mime, const char *name, const char *prefix);
extern size_t headersEnd(const char *, size_t);
extern const char *mime_get_auth(const char *hdr, const char *auth_scheme, const char **auth_field);

extern void mimeInit(char *filename);
extern void mimeFreeMemory(void);
extern char *mimeGetContentEncoding(const char *fn);
extern char *mimeGetContentType(const char *fn);
extern char *mimeGetIcon(const char *fn);
extern const char *mimeGetIconURL(const char *fn);
extern char mimeGetTransferMode(const char *fn);
extern int mimeGetDownloadOption(const char *fn);
extern int mimeGetViewOption(const char *fn);

extern int mcastSetTtl(int, int);
extern IPH mcastJoinGroups;

/* Labels for hierachical log file */
/* put them all here for easier reference when writing a logfile analyzer */


extern peer *getFirstPeer(void);
extern peer *getFirstUpParent(request_t *);
extern peer *getNextPeer(peer *);
extern peer *getSingleParent(request_t *);
extern int neighborsCount(request_t *);
extern int neighborsUdpPing(request_t *,
    StoreEntry *,
    IRCB * callback,
    void *data,
    int *exprep,
    int *timeout);
extern void neighborAddAcl(const char *, const char *);
extern void neighborsUdpAck(const cache_key *, icp_common_t *, const struct sockaddr_in *);
extern void neighborAdd(const char *, const char *, int, int, int, int, int);
extern void neighbors_open(int);
extern peer *peerFindByName(const char *);
extern peer *peerFindByNameAndPort(const char *, unsigned short);
extern peer *getDefaultParent(request_t * request);
extern peer *getRoundRobinParent(request_t * request);
extern peer *getAnyParent(request_t * request);
extern lookup_t peerDigestLookup(peer * p, request_t * request, StoreEntry * entry);
extern peer *neighborsDigestSelect(request_t * request, StoreEntry * entry);
extern void peerNoteDigestLookup(request_t * request, peer * p, lookup_t lookup);
extern void peerNoteDigestGone(peer * p);
extern int neighborUp(const peer * e);
extern CBDUNL peerDestroy;
extern char *neighborTypeStr(const peer * e);
extern peer_t neighborType(const peer *, const request_t *);
extern void peerCheckConnectStart(peer *);
extern void dump_peer_options(StoreEntry *, peer *);
extern int peerHTTPOkay(const peer *, request_t *);
extern peer *whichPeer(const struct sockaddr_in *from);
#if USE_HTCP
extern void neighborsHtcpReply(const cache_key *, htcpReplyData *, const struct sockaddr_in *);
#endif

extern void netdbInit(void);
extern void netdbHandlePingReply(const struct sockaddr_in *from, int hops, int rtt);
extern void netdbPingSite(const char *hostname);
extern void netdbInit(void);
extern void netdbDump(StoreEntry *);
extern int netdbHops(struct in_addr);
extern void netdbFreeMemory(void);
extern int netdbHostHops(const char *host);
extern int netdbHostRtt(const char *host);
extern int netdbHostPeerRtt(const char *host, peer * peer);
extern void netdbUpdatePeer(request_t *, peer * e, int rtt, int hops);
extern void netdbDeleteAddrNetwork(struct in_addr addr);
extern int netdbHostPeerRtt(const char *host, peer * peer);
extern void netdbBinaryExchange(StoreEntry *);
extern EVH netdbExchangeStart;
extern void netdbExchangeUpdatePeer(struct in_addr, peer *, double, double);
extern peer *netdbClosestParent(request_t *);
extern void netdbHostData(const char *host, int *samp, int *rtt, int *hops);

extern void cachemgrStart(int fd, request_t * request, StoreEntry * entry);
extern void cachemgrRegister(const char *, const char *, OBJH *, int, int);
extern void cachemgrInit(void);

extern void peerSelect(request_t *, StoreEntry *, PSC *, void *data);
extern void peerSelectInit(void);

/* peer_digest.c */
extern PeerDigest *peerDigestCreate(peer * p);
extern void peerDigestNeeded(PeerDigest * pd);
extern void peerDigestNotePeerGone(PeerDigest * pd);
extern void peerDigestStatsReport(const PeerDigest * pd, StoreEntry * e);

/* forward.c */
extern void fwdStart(int, StoreEntry *, request_t *);
extern DEFER fwdCheckDeferRead;
extern void fwdFail(FwdState *, ErrorState *);
extern void fwdUnregister(int fd, FwdState *);
extern void fwdComplete(FwdState * fwdState);
extern void fwdInit(void);
extern int fwdReforwardableStatus(http_status s);
extern void fwdServersFree(FwdServer ** FS);

extern void urnStart(request_t *, StoreEntry *);

extern void redirectStart(clientHttpRequest *, RH *, void *);
extern void redirectInit(void);
extern void redirectShutdown(void);

extern void authenticateStart(acl_proxy_auth_user *, RH *, void *);
extern void authenticateInit(void);
extern void authenticateShutdown(void);

extern void refreshAddToList(const char *, int, time_t, int, time_t);
extern int refreshIsCachable(const StoreEntry *);
extern int refreshCheckHTTP(const StoreEntry *, request_t *);
extern int refreshCheckICP(const StoreEntry *, request_t *);
extern int refreshCheckHTCP(const StoreEntry *, request_t *);
extern int refreshCheckDigest(const StoreEntry *, time_t delta);
extern time_t getMaxAge(const char *url);
extern void refreshInit(void);

extern void serverConnectionsClose(void);
extern void shut_down(int);


extern void start_announce(void *unused);
extern void sslStart(int fd, const char *, request_t *, size_t * sz);
extern void waisStart(FwdState *);

/* ident.c */
#if USE_IDENT
extern void identStart(struct sockaddr_in *me, struct sockaddr_in *peer, IDCB * callback, void *cbdata);
extern void identInit(void);
#endif

extern void statInit(void);
extern void statFreeMemory(void);
extern double median_svc_get(int, int);
extern void pconnHistCount(int, int);
extern int stat5minClientRequests(void);
extern double stat5minCPUUsage(void);
extern const char *storeEntryFlags(const StoreEntry *);
extern double statRequestHitRatio(int minutes);
extern double statByteHitRatio(int minutes);



/* StatHist */
extern void statHistClean(StatHist * H);
extern void statHistCount(StatHist * H, double val);
extern void statHistCopy(StatHist * Dest, const StatHist * Orig);
extern void statHistSafeCopy(StatHist * Dest, const StatHist * Orig);
extern double statHistDeltaMedian(const StatHist * A, const StatHist * B);
extern void statHistDump(const StatHist * H, StoreEntry * sentry, StatHistBinDumper bd);
extern void statHistLogInit(StatHist * H, int capacity, double min, double max);
extern void statHistEnumInit(StatHist * H, int last_enum);
extern void statHistIntInit(StatHist * H, int n);
extern StatHistBinDumper statHistEnumDumper;
extern StatHistBinDumper statHistIntDumper;


/* MemMeter */
extern void memMeterSyncHWater(MemMeter * m);
#define memMeterCheckHWater(m) { if ((m).hwater_level < (m).level) memMeterSyncHWater(&(m)); }
#define memMeterInc(m) { (m).level++; memMeterCheckHWater(m); }
#define memMeterDec(m) { (m).level--; }
#define memMeterAdd(m, sz) { (m).level += (sz); memMeterCheckHWater(m); }
#define memMeterDel(m, sz) { (m).level -= (sz); }

/* mem */
extern void memInit(void);
extern void memClean(void);
extern void memInitModule(void);
extern void memCleanModule(void);
extern void memConfigure(void);
extern void *memAllocate(mem_type);
extern void *memAllocBuf(size_t net_size, size_t * gross_size);
extern CBDUNL memFree;
extern void memFreeBuf(size_t size, void *);
extern void memFree2K(void *);
extern void memFree4K(void *);
extern void memFree8K(void *);
extern void memFreeDISK(void *);
extern int memInUse(mem_type);
extern size_t memTotalAllocated(void);
extern void memDataInit(mem_type, const char *, size_t, int);
extern void memCheckInit(void);

/* MemPool */
extern MemPool *memPoolCreate(const char *label, size_t obj_size);
extern void memPoolDestroy(MemPool * pool);
extern void *memPoolAlloc(MemPool * pool);
extern void memPoolFree(MemPool * pool, void *obj);
extern int memPoolWasUsed(const MemPool * pool);
extern int memPoolInUseCount(const MemPool * pool);
extern size_t memPoolInUseSize(const MemPool * pool);
extern int memPoolUsedCount(const MemPool * pool);
extern void memPoolReport(const MemPool * pool, StoreEntry * e);

/* Mem */
extern void memReport(StoreEntry * e);

extern int stmemFreeDataUpto(mem_hdr *, int);
extern void stmemAppend(mem_hdr *, const char *, int);
extern ssize_t stmemCopy(const mem_hdr *, off_t, char *, size_t);
extern void stmemFree(mem_hdr *);
extern void stmemFreeData(mem_hdr *);

/* ----------------------------------------------------------------- */

/*
 * store.c
 */
extern StoreEntry *new_StoreEntry(int, const char *, const char *);
extern StoreEntry *storeGet(const cache_key *);
extern StoreEntry *storeGetPublic(const char *uri, const method_t method);
extern StoreEntry *storeCreateEntry(const char *, const char *, request_flags, method_t);
extern void storeSetPublicKey(StoreEntry *);
extern void storeComplete(StoreEntry *);
extern void storeInit(void);
extern int storeClientWaiting(const StoreEntry *);
extern void storeAbort(StoreEntry *);
extern void storeAppend(StoreEntry *, const char *, int);
extern void storeLockObject(StoreEntry *);
extern void storeRelease(StoreEntry *);
extern int storeUnlockObject(StoreEntry *);
extern int storeUnregister(StoreEntry *, void *);
extern void storeClientCopy(StoreEntry * e,
    off_t seen_offset,
    off_t copy_offset,
    size_t size,
    char *buf,
    STCB * callback,
    void *data);
extern int storePendingNClients(const StoreEntry *);
extern EVH storeMaintainSwapSpace;
extern void storeExpireNow(StoreEntry *);
extern void storeReleaseRequest(StoreEntry *);
extern off_t storeLowestMemReaderOffset(const StoreEntry *);
extern void storeConfigure(void);
extern void storeNegativeCache(StoreEntry *);
extern void storeFreeMemory(void);
extern int expiresMoreThan(time_t, time_t);
extern int storeClientCopyPending(StoreEntry *, void *);
extern void InvokeHandlers(StoreEntry *);
extern int storeEntryValidToSend(StoreEntry *);
extern void storeTimestampsSet(StoreEntry *);
#if !HEAP_REPLACEMENT
extern time_t storeExpiredReferenceAge(void);
#endif
extern void storeRegisterAbort(StoreEntry * e, STABH * cb, void *);
extern void storeUnregisterAbort(StoreEntry * e);
extern void storeMemObjectDump(MemObject * mem);
extern void storeEntryDump(const StoreEntry * e, int debug_lvl);
extern const char *storeUrl(const StoreEntry *);
extern void storeCreateMemObject(StoreEntry *, const char *, const char *);
extern void storeCopyNotModifiedReplyHeaders(MemObject * O, MemObject * N);
extern void storeBuffer(StoreEntry *);
extern void storeBufferFlush(StoreEntry *);
extern void storeHashInsert(StoreEntry * e, const cache_key *);
extern void storeSetMemStatus(StoreEntry * e, int);
#if STDC_HEADERS
extern void storeAppendPrintf(StoreEntry *, const char *,...);
#else
extern void storeAppendPrintf();
#endif
extern void storeAppendVPrintf(StoreEntry *, const char *, va_list ap);
extern int storeCheckCachable(StoreEntry * e);
extern void storeSetPrivateKey(StoreEntry *);
extern int objectLen(const StoreEntry * e);
extern int contentLen(const StoreEntry * e);
extern HttpReply *storeEntryReply(StoreEntry *);
extern int storeTooManyDiskFilesOpen(void);
extern void storeEntryReset(StoreEntry *);
extern void storeHeapPositionUpdate(StoreEntry *);

/* store_io.c */
extern STOBJOPEN storeOpen;
extern STOBJCLOSE storeClose;
extern STOBJREAD storeRead;
extern STOBJWRITE storeWrite;
extern STOBJUNLINK storeUnlink;
extern off_t storeOffset(storeIOState *);

/*
 * store_io_ufs.c
 */
extern storeIOState *storeUfsOpen(sfileno, mode_t, STIOCB *, void *);
extern void storeUfsClose(storeIOState * sio);
extern void storeUfsRead(storeIOState *, char *, size_t, off_t, STRCB *, void *);
extern void storeUfsWrite(storeIOState *, char *, size_t, off_t, FREE *);
extern void storeUfsUnlink(int fileno);

#if USE_ASYNC_IO
/*
 * store_io_ufs.c
 */
extern storeIOState *storeAufsOpen(sfileno, mode_t, STIOCB *, void *);
extern void storeAufsClose(storeIOState * sio);
extern void storeAufsRead(storeIOState *, char *, size_t, off_t, STRCB *, void *);
extern void storeAufsWrite(storeIOState *, char *, size_t, off_t, FREE *);
extern void storeAufsUnlink(int fileno);
#endif

/*
 * store_log.c
 */
extern void storeLog(int tag, const StoreEntry * e);
extern void storeLogRotate(void);
extern void storeLogClose(void);
extern void storeLogOpen(void);


/*
 * store_key_*.c
 */
extern const cache_key *storeKeyDup(const cache_key *);
extern cache_key *storeKeyCopy(cache_key *, const cache_key *);
extern void storeKeyFree(const cache_key *);
extern const cache_key *storeKeyScan(const char *);
extern const char *storeKeyText(const cache_key *);
extern const cache_key *storeKeyPublic(const char *, const method_t);
extern const cache_key *storeKeyPrivate(const char *, method_t, int);
extern int storeKeyHashBuckets(int);
extern int storeKeyNull(const cache_key *);
extern void storeKeyInit(void);
extern HASHHASH storeKeyHashHash;
extern HASHCMP storeKeyHashCmp;

/*
 * store_digest.c
 */
extern void storeDigestInit(void);
extern void storeDigestNoteStoreReady(void);
extern void storeDigestScheduleRebuild(void);
extern void storeDigestDel(const StoreEntry * entry);
extern void storeDigestReport(StoreEntry *);

/*
 * store_dir.c
 */
extern OBJH storeDirStats;
extern char *storeDirSwapLogFile(int, const char *);
extern char *storeSwapDir(int);
extern char *storeSwapFullPath(int, char *);
extern char *storeSwapSubSubDir(int, char *);
extern const char *storeSwapPath(int);
extern int storeDirMapAllocate(void);
extern int storeDirMapBitTest(int fn);
extern int storeDirMapBitsInUse(void);
extern int storeDirNumber(int fileno);
extern int storeDirProperFileno(int dirn, int fn);
extern int storeDirValidFileno(int fn, int);
extern int storeDirWriteCleanLogs(int reopen);
extern int storeVerifySwapDirs(void);
extern void storeCreateSwapDirectories(void);
extern void storeDirCloseSwapLogs(void);
extern void storeDirCloseTmpSwapLog(int dirn);
extern void storeDirConfigure(void);
extern void storeDirDiskFull(int fn);
extern void storeDirInit(void);
extern void storeDirMapBitReset(int fn);
extern void storeDirMapBitSet(int fn);
extern void storeDirOpenSwapLogs(void);
extern void storeDirSwapLog(const StoreEntry *, int op);
extern void storeDirUpdateSwapSize(int fn, size_t size, int sign);

/*
 * store_dir_ufs.c
 */
extern OBJH storeUfsDirStats;
extern void storeUfsDirParse(cacheSwap * swap);
extern void storeUfsDirDump(StoreEntry * entry, const char *name, SwapDir * s);
extern void storeUfsDirFree(SwapDir *);
extern char *storeUfsFullPath(sfileno fn, char *fullpath);
#if USE_ASYNC_IO
extern void storeAufsDirParse(cacheSwap * swap);
#endif


/*
 * store_swapmeta.c
 */
extern char *storeSwapMetaPack(tlv * tlv_list, int *length);
extern tlv *storeSwapMetaBuild(StoreEntry * e);
extern tlv *storeSwapMetaUnpack(const char *buf, int *hdrlen);
extern void storeSwapTLVFree(tlv * n);

/*
 * store_rebuild.c
 */
extern void storeRebuildStart(void);
extern void storeRebuildComplete(struct _store_rebuild_data *);

/*
 * store_swapin.c
 */
extern void storeSwapInStart(store_client *);

/*
 * store_swapout.c
 */
extern void storeSwapOut(StoreEntry * e);
extern void storeSwapOutFileClose(StoreEntry * e);
extern int storeSwapOutAble(const StoreEntry * e);

/*
 * store_client.c
 */
extern store_client *storeClientListSearch(const MemObject * mem, void *data);
extern void storeClientListAdd(StoreEntry * e, void *data);
extern void storeClientCopy(StoreEntry *, off_t, off_t, size_t, char *, STCB *, void *);
extern int storeClientCopyPending(StoreEntry * e, void *data);
extern int storeUnregister(StoreEntry * e, void *data);
extern off_t storeLowestMemReaderOffset(const StoreEntry * entry);
extern void InvokeHandlers(StoreEntry * e);
extern int storePendingNClients(const StoreEntry * e);


extern const char *getMyHostname(void);
extern const char *uniqueHostname(void);
extern void safeunlink(const char *path, int quiet);
extern void death(int sig);
extern void fatal(const char *message);
#if STDC_HEADERS
extern void fatalf(const char *fmt,...);
#else
extern void fatalf();
#endif
extern void fatal_dump(const char *message);
extern void sigusr2_handle(int sig);
extern void sig_child(int sig);
extern void leave_suid(void);
extern void enter_suid(void);
extern void no_suid(void);
extern void writePidFile(void);
extern void setSocketShutdownLifetimes(int);
extern void setMaxFD(void);
extern time_t getCurrentTime(void);
extern int percent(int, int);
extern double dpercent(double, double);
extern void squid_signal(int sig, SIGHDLR *, int flags);
extern pid_t readPidFile(void);
extern struct in_addr inaddrFromHostent(const struct hostent *hp);
extern int intAverage(int, int, int, int);
extern double doubleAverage(double, double, int, int);
extern void debug_trap(const char *);
extern void logsFlush(void);
extern char *checkNullString(char *p);
extern void squid_getrusage(struct rusage *r);
extern double rusage_cputime(struct rusage *r);
extern int rusage_maxrss(struct rusage *r);
extern int rusage_pagefaults(struct rusage *r);
extern void releaseServerSockets(void);
extern void PrintRusage(void);
extern void dumpMallocStats(void);

extern void pumpInit(int fd, request_t * r, char *uri);
extern void pumpStart(int, FwdState *, CWCB * callback, void *);
extern int pumpMethod(method_t method);
extern int pumpRestart(request_t *);

extern void unlinkdInit(void);
extern void unlinkdClose(void);
extern void unlinkdUnlink(const char *);

extern char *url_convert_hex(char *org_url, int allocate);
extern char *url_escape(const char *url);
extern protocol_t urlParseProtocol(const char *);
extern method_t urlParseMethod(const char *);
extern void urlInitialize(void);
extern request_t *urlParse(method_t, char *);
extern const char *urlCanonical(request_t *);
extern char *urlRInternal(const char *host, u_short port, const char *dir, const char *name);
extern char *urlInternal(const char *dir, const char *name);
extern int matchDomainName(const char *host, const char *domain);
extern int urlCheckRequest(const request_t *);
extern int urlDefaultPort(protocol_t p);
extern char *urlCanonicalClean(const request_t *);
extern char *urlHostname(const char *url);

extern void useragentOpenLog(void);
extern void useragentRotateLog(void);
extern void logUserAgent(const char *, const char *);
extern peer_t parseNeighborType(const char *s);

extern void errorInitialize(void);
extern void errorClean(void);
extern HttpReply *errorBuildReply(ErrorState * err);
extern void errorSend(int fd, ErrorState *);
extern void errorAppendEntry(StoreEntry *, ErrorState *);
extern void errorStateFree(ErrorState * err);
extern int errorReservePageId(const char *page_name);
extern ErrorState *errorCon(err_type type, http_status);

extern void pconnPush(int, const char *host, u_short port);
extern int pconnPop(const char *host, u_short port);
extern void pconnInit(void);

extern int asnMatchIp(void *, struct in_addr);
extern void asnInit(void);
extern void asnFreeMemory(void);

/* tools.c */
extern void dlinkAdd(void *data, dlink_node *, dlink_list *);
extern void dlinkAddTail(void *data, dlink_node *, dlink_list *);
extern void dlinkDelete(dlink_node * m, dlink_list * list);
extern void kb_incr(kb_t *, size_t);
extern double gb_to_double(const gb_t *);
extern const char *gb_to_str(const gb_t *);
extern void gb_flush(gb_t *);	/* internal, do not use this */
extern int stringHasWhitespace(const char *);
extern int stringHasCntl(const char *);
extern void linklistPush(link_list **, void *);
extern void *linklistShift(link_list **);
extern int xrename(const char *from, const char *to);

#if USE_HTCP
extern void htcpInit(void);
extern void htcpQuery(StoreEntry * e, request_t * req, peer * p);
extern void htcpSocketShutdown(void);
extern void htcpSocketClose(void);
#endif

/* String */
#define strLen(s)     ((const int)(s).len)
#define strBuf(s)     ((const char*)(s).buf)
#define strChr(s,ch)  ((const char*)strchr(strBuf(s), (ch)))
#define strRChr(s,ch) ((const char*)strrchr(strBuf(s), (ch)))
#define strStr(s,str) ((const char*)strstr(strBuf(s), (str)))
#define strCmp(s,str)     strcmp(strBuf(s), (str))
#define strNCmp(s,str,n)     strncmp(strBuf(s), (str), (n))
#define strCaseCmp(s,str) strcasecmp(strBuf(s), (str))
#define strNCaseCmp(s,str,n) strncasecmp(strBuf(s), (str), (n))
#define strSet(s,ptr,ch) (s).buf[ptr-(s).buf] = (ch)
#define strCut(s,pos) (((s).len = pos) , ((s).buf[pos] = '\0'))
#define strCutPtr(s,ptr) (((s).len = (ptr)-(s).buf) , ((s).buf[(s).len] = '\0'))
/* #define strCat(s,str)  stringAppend(&(s), (str), strlen(str)+1) */
extern void stringInit(String * s, const char *str);
extern void stringLimitInit(String * s, const char *str, int len);
extern String stringDup(const String * s);
extern void stringClean(String * s);
extern void stringReset(String * s, const char *str);
extern void stringAppend(String * s, const char *buf, int len);
/* extern void stringAppendf(String *s, const char *fmt, ...); */

/*
 * ipc.c
 */
extern int ipcCreate(int type,
    const char *prog,
    char *const args[],
    const char *name,
    int *rfd,
    int *wfd);

/* CacheDigest */
extern CacheDigest *cacheDigestCreate(int capacity, int bpe);
extern void cacheDigestDestroy(CacheDigest * cd);
extern CacheDigest *cacheDigestClone(const CacheDigest * cd);
extern void cacheDigestClear(CacheDigest * cd);
extern void cacheDigestChangeCap(CacheDigest * cd, int new_cap);
extern int cacheDigestTest(const CacheDigest * cd, const cache_key * key);
extern void cacheDigestAdd(CacheDigest * cd, const cache_key * key);
extern void cacheDigestDel(CacheDigest * cd, const cache_key * key);
extern size_t cacheDigestCalcMaskSize(int cap, int bpe);
extern int cacheDigestBitUtil(const CacheDigest * cd);
extern void cacheDigestGuessStatsUpdate(cd_guess_stats * stats, int real_hit, int guess_hit);
extern void cacheDigestGuessStatsReport(const cd_guess_stats * stats, StoreEntry * sentry, const char *label);
extern void cacheDigestReport(CacheDigest * cd, const char *label, StoreEntry * e);

extern void internalStart(request_t *, StoreEntry *);
extern int internalCheck(const char *urlpath);
extern int internalStaticCheck(const char *urlpath);
extern char *internalLocalUri(const char *dir, const char *name);
extern char *internalRemoteUri(const char *, u_short, const char *, const char *);
extern const char *internalHostname(void);
extern int internalHostnameIs(const char *);

#if USE_CARP
extern void carpInit(void);
extern peer *carpSelectParent(request_t *);
#endif

#if DELAY_POOLS
extern void delayPoolsInit(void);
extern void delayInitDelayData(unsigned short pools);
extern void delayFreeDelayData(void);
extern void delayCreateDelayPool(unsigned short pool, u_char class);
extern void delayInitDelayPool(unsigned short pool, u_char class, delaySpecSet * rates);
extern void delayFreeDelayPool(unsigned short pool);
extern void delayPoolsReconfigure(void);
extern void delaySetNoDelay(int fd);
extern void delayClearNoDelay(int fd);
extern int delayIsNoDelay(int fd);
extern delay_id delayClient(request_t *);
extern EVH delayPoolsUpdate;
extern int delayBytesWanted(delay_id d, int min, int max);
extern void delayBytesIn(delay_id, int qty);
extern int delayMostBytesWanted(const MemObject * mem, int max);
extern delay_id delayMostBytesAllowed(const MemObject * mem);
extern void delaySetStoreClient(StoreEntry * e, void *data, delay_id delay_id);
extern void delayRegisterDelayIdPtr(delay_id * loc);
extern void delayUnregisterDelayIdPtr(delay_id * loc);
#endif

/* helper.c */
extern void helperOpenServers(helper * hlp);
extern void helperSubmit(helper * hlp, const char *buf, HLPCB * callback, void *data);
extern void helperStats(StoreEntry * sentry, helper * hlp);
extern void helperShutdown(helper * hlp);
extern helper *helperCreate(const char *);
extern void helperFree(helper *);

#if USE_LEAKFINDER
extern void leakInit(void);
extern void *leakAddFL(void *, const char *, int);
extern void *leakTouchFL(void *, const char *, int);
extern void *leakFree(void *);
#endif

/*
 * prototypes for system functions missing from system includes
 */

#ifdef _SQUID_SOLARIS_
extern int getrusage(int, struct rusage *);
extern int getpagesize(void);
extern int gethostname(char *, int);
#endif
