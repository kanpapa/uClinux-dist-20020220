
/*
 * $Id: errorpage.c,v 1.151.2.4 2000/07/13 05:32:26 wessels Exp $
 *
 * DEBUG: section 4     Error Generation
 * AUTHOR: Duane Wessels
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

/*
 * Abstract:  These routines are used to generate error messages to be
 *              sent to clients.  The error type is used to select between
 *              the various message formats. (formats are stored in the
 *              Config.errorDirectory)
 */

#include "squid.h"


/* local types */

typedef struct {
    int id;
    char *page_name;
} ErrorDynamicPageInfo;

/* local constant and vars */

static const char *const proxy_auth_challenge_fmt = "Basic realm=\"%s\"";

/*
 * note: hard coded error messages are not appended with %S automagically
 * to give you more control on the format
 */
static const struct {
    int type;			/* and page_id */
    const char *text;
} error_hard_text[] = {

    {
	ERR_SQUID_SIGNATURE,
	    "\n<br clear=\"all\">\n"
	    "<hr noshade size=1>\n"
	    "Generated %T by %h (%s)\n"
	    "</BODY></HTML>\n"
    }
};

static Stack ErrorDynamicPages;

/* local prototypes */

static const int error_hard_text_count = sizeof(error_hard_text) / sizeof(*error_hard_text);
static char **error_text = NULL;
static int error_page_count = 0;

static char *errorTryLoadText(const char *page_name, const char *dir);
static char *errorLoadText(const char *page_name);
static const char *errorFindHardText(err_type type);
static ErrorDynamicPageInfo *errorDynamicPageInfoCreate(int id, const char *page_name);
static void errorDynamicPageInfoDestroy(ErrorDynamicPageInfo * info);
static MemBuf errorBuildContent(ErrorState * err);
static const char *errorConvert(char token, ErrorState * err);
static CWCB errorSendComplete;

/*
 * Function:  errorInitialize
 *
 * Abstract:  This function finds the error messages formats, and stores
 *            them in error_text[];
 *
 * Global effects:
 *            error_text[] - is modified
 */
void
errorInitialize(void)
{
    err_type i;
    const char *text;
    error_page_count = ERR_MAX + ErrorDynamicPages.count;
    error_text = xcalloc(error_page_count, sizeof(char *));
    for (i = ERR_NONE, i++; i < error_page_count; i++) {
	safe_free(error_text[i]);
	/* hard-coded ? */
	if ((text = errorFindHardText(i)))
	    error_text[i] = xstrdup(text);
	else if (i < ERR_MAX) {
	    /* precompiled ? */
	    error_text[i] = errorLoadText(err_type_str[i]);
	} else {
	    /* dynamic */
	    ErrorDynamicPageInfo *info = ErrorDynamicPages.items[i - ERR_MAX];
	    assert(info && info->id == i && info->page_name);
	    error_text[i] = errorLoadText(info->page_name);
	}
	assert(error_text[i]);
    }
}

void
errorClean(void)
{
    if (error_text) {
	int i;
	for (i = ERR_NONE + 1; i < error_page_count; i++)
	    safe_free(error_text[i]);
	safe_free(error_text);
    }
    while (ErrorDynamicPages.count)
	errorDynamicPageInfoDestroy(stackPop(&ErrorDynamicPages));
    error_page_count = 0;
}

static const char *
errorFindHardText(err_type type)
{
    int i;
    for (i = 0; i < error_hard_text_count; i++)
	if (error_hard_text[i].type == type)
	    return error_hard_text[i].text;
    return NULL;
}


static char *
errorLoadText(const char *page_name)
{
    /* test configured location */
    char *text = errorTryLoadText(page_name, Config.errorDirectory);
    /* test default location if failed */
    if (!text && strcmp(Config.errorDirectory, DEFAULT_SQUID_ERROR_DIR))
	text = errorTryLoadText(page_name, DEFAULT_SQUID_ERROR_DIR);
    /* giving up if failed */
    if (!text)
	fatal("failed to find or read error text file.");
    return text;
}

static char *
errorTryLoadText(const char *page_name, const char *dir)
{
    int fd;
    char path[MAXPATHLEN];
    struct stat sb;
    char *text;

    snprintf(path, sizeof(path), "%s/%s", dir, page_name);
    fd = file_open(path, O_RDONLY);
    if (fd < 0 || fstat(fd, &sb) < 0) {
	debug(4, 0) ("errorTryLoadText: '%s': %s\n", path, xstrerror());
	if (fd >= 0)
	    file_close(fd);
	return NULL;
    }
    text = xcalloc(sb.st_size + 2 + 1, 1);	/* 2 == space for %S */
    if (read(fd, text, sb.st_size) != sb.st_size) {
	debug(4, 0) ("errorTryLoadText: failed to fully read: '%s': %s\n",
	    path, xstrerror());
	xfree(text);
	text = NULL;
    }
    file_close(fd);
    if (strstr(text, "%s") == NULL)
	strcat(text, "%S");	/* add signature */
    return text;
}

static ErrorDynamicPageInfo *
errorDynamicPageInfoCreate(int id, const char *page_name)
{
    ErrorDynamicPageInfo *info = xcalloc(1, sizeof(ErrorDynamicPageInfo));
    info->id = id;
    info->page_name = xstrdup(page_name);
    return info;
}

static void
errorDynamicPageInfoDestroy(ErrorDynamicPageInfo * info)
{
    assert(info);
    xfree(info->page_name);
    xfree(info);
}

int
errorReservePageId(const char *page_name)
{
    ErrorDynamicPageInfo *info =
    errorDynamicPageInfoCreate(ERR_MAX + ErrorDynamicPages.count, page_name);
    stackPush(&ErrorDynamicPages, info);
    return info->id;
}

static const char *
errorPageName(int pageId)
{
    if (pageId >= ERR_NONE && pageId < ERR_MAX)		/* common case */
	return err_type_str[pageId];
    if (pageId >= ERR_MAX && pageId - ERR_MAX < ErrorDynamicPages.count)
	return ((ErrorDynamicPageInfo *) ErrorDynamicPages.
	    items[pageId - ERR_MAX])->page_name;
    return "ERR_UNKNOWN";	/* should not happen */
}

/*
 * Function:  errorCon
 *
 * Abstract:  This function creates a ErrorState object.
 */
ErrorState *
errorCon(err_type type, http_status status)
{
    ErrorState *err = memAllocate(MEM_ERRORSTATE);
    err->page_id = type;	/* has to be reset manually if needed */
    err->type = type;
    err->http_status = status;
    return err;
}

/*
 * Function:  errorAppendEntry
 *
 * Arguments: err - This object is destroyed after use in this function.
 *
 * Abstract:  This function generates a error page from the info contained
 *            by 'err' and then stores the text in the specified store
 *            entry.  This function should only be called by ``server
 *            side routines'' which need to communicate errors to the
 *            client side.  It should also be called from client_side.c
 *            because we now support persistent connections, and
 *            cannot assume that we can immediately write to the socket
 *            for an error.
 */
void
errorAppendEntry(StoreEntry * entry, ErrorState * err)
{
    HttpReply *rep;
    MemObject *mem = entry->mem_obj;
    assert(mem != NULL);
    assert(mem->inmem_hi == 0);
    if (entry->store_status != STORE_PENDING) {
	/*
	 * If the entry is not STORE_PENDING, then no clients
	 * care about it, and we don't need to generate an
	 * error message
	 */
	assert(EBIT_TEST(entry->flags, ENTRY_ABORTED));
	assert(mem->nclients == 0);
	errorStateFree(err);
	return;
    }
    storeLockObject(entry);
    storeBuffer(entry);
    rep = errorBuildReply(err);
    /* Add authentication header */
    switch (err->http_status) {
    case HTTP_PROXY_AUTHENTICATION_REQUIRED:
	/* Proxy authorisation needed */
	httpHeaderPutStrf(&rep->header, HDR_PROXY_AUTHENTICATE,
	    proxy_auth_challenge_fmt, Config.proxyAuthRealm);
	break;
    case HTTP_UNAUTHORIZED:
	/* WWW Authorisation needed */
	httpHeaderPutStrf(&rep->header, HDR_WWW_AUTHENTICATE,
	    proxy_auth_challenge_fmt, Config.proxyAuthRealm);
	break;
    default:
	/* Keep GCC happy */
	break;
    }
    httpReplySwapOut(rep, entry);
    httpReplyDestroy(rep);
    mem->reply->sline.status = err->http_status;
    mem->reply->content_length = -1;
    EBIT_CLR(entry->flags, ENTRY_FWD_HDR_WAIT);
    storeBufferFlush(entry);
    storeComplete(entry);
    storeNegativeCache(entry);
    storeReleaseRequest(entry);
    storeUnlockObject(entry);
    errorStateFree(err);
}

/*
 * Function:  errorSend
 *
 * Arguments: err - This object is destroyed after use in this function.
 *
 * Abstract:  This function generates a error page from the info contained
 *            by 'err' and then sends it to the client.
 *            The callback function errorSendComplete() is called after
 *            the page has been written to the client socket (fd).
 *            errorSendComplete() deallocates 'err'.  We need to add
 *            'err' to the cbdata because comm_write() requires it
 *            for all callback data pointers.
 *
 *            Note, normally errorSend() should only be called from
 *            routines in ssl.c and pass.c, where we don't have any
 *            StoreEntry's.  In client_side.c we must allocate a StoreEntry
 *            for errors and use errorAppendEntry() to account for
 *            persistent/pipeline connections.
 */
void
errorSend(int fd, ErrorState * err)
{
    HttpReply *rep;
    debug(4, 3) ("errorSend: FD %d, err=%p\n", fd, err);
    assert(fd >= 0);
    /*
     * ugh, this is how we make sure error codes get back to
     * the client side for logging and error tracking.
     */
    if (err->request)
	err->request->err_type = err->type;
    /* moved in front of errorBuildBuf @?@ */
    err->flags.flag_cbdata = 1;
    cbdataAdd(err, memFree, MEM_ERRORSTATE);
    rep = errorBuildReply(err);
    comm_write_mbuf(fd, httpReplyPack(rep), errorSendComplete, err);
    httpReplyDestroy(rep);
}

/*
 * Function:  errorSendComplete
 *
 * Abstract:  Called by commHandleWrite() after data has been written
 *            to the client socket.
 *
 * Note:      If there is a callback, the callback is responsible for
 *            closeing the FD, otherwise we do it ourseves.
 */
static void
errorSendComplete(int fd, char *bufnotused, size_t size, int errflag, void *data)
{
    ErrorState *err = data;
    debug(4, 3) ("errorSendComplete: FD %d, size=%d\n", fd, size);
    if (errflag != COMM_ERR_CLOSING) {
	if (err->callback)
	    err->callback(fd, err->callback_data, size);
	else
	    comm_close(fd);
    }
    errorStateFree(err);
}

void
errorStateFree(ErrorState * err)
{
    requestUnlink(err->request);
    safe_free(err->redirect_url);
    safe_free(err->url);
    safe_free(err->host);
    safe_free(err->dnsserver_msg);
    safe_free(err->request_hdrs);
    wordlistDestroy(&err->ftp.server_msg);
    safe_free(err->ftp.request);
    safe_free(err->ftp.reply);
    if (err->flags.flag_cbdata)
	cbdataFree(err);
    else
	memFree(err, MEM_ERRORSTATE);
}

#define CVT_BUF_SZ 512

/*
 * B - URL with FTP %2f hack                    x
 * c - Squid error code                         x
 * d - seconds elapsed since request received   x
 * e - errno                                    x
 * E - strerror()                               x
 * f - FTP request line                         x
 * F - FTP reply line                           x
 * g - FTP server message                       x
 * h - cache hostname                           x
 * H - server host name                         x
 * i - client IP address                        x
 * I - server IP address                        x
 * L - HREF link for more info/contact          x
 * M - Request Method                           x
 * p - URL port #                               x
 * P - Protocol                                 x
 * R - Full HTTP Request                        x
 * S - squid signature from ERR_SIGNATURE       x
 * s - caching proxy software with version      x
 * t - local time                               x
 * T - UTC                                      x
 * U - URL without password                     x
 * u - URL without password, %2f added to path  x
 * w - cachemgr email address                   x
 * z - dns server error message                 x
 */

static const char *
errorConvert(char token, ErrorState * err)
{
    request_t *r = err->request;
    static MemBuf mb = MemBufNULL;
    const char *p = NULL;	/* takes priority over mb if set */

    memBufReset(&mb);
    switch (token) {
    case 'B':
	p = r ? ftpUrlWith2f(r) : "[no URL]";
	break;
    case 'c':
	assert(err->type >= ERR_NONE);
	assert(err->type < ERR_MAX);
	p = err_type_str[err->type];
	break;
    case 'e':
	memBufPrintf(&mb, "%d", err->xerrno);
	break;
    case 'E':
	if (err->xerrno)
	    memBufPrintf(&mb, "(%d) %s", err->xerrno, strerror(err->xerrno));
	else
	    memBufPrintf(&mb, "[No Error]");
	break;
    case 'f':
	/* FTP REQUEST LINE */
	if (err->ftp.request)
	    p = err->ftp.request;
	else
	    p = "nothing";
	break;
    case 'F':
	/* FTP REPLY LINE */
	if (err->ftp.request)
	    p = err->ftp.reply;
	else
	    p = "nothing";
	break;
    case 'g':
	/* FTP SERVER MESSAGE */
	wordlistCat(err->ftp.server_msg, &mb);
	break;
    case 'h':
	memBufPrintf(&mb, "%s", getMyHostname());
	break;
    case 'H':
	p = r ? r->host : "[unknown host]";
	break;
    case 'i':
	memBufPrintf(&mb, "%s", inet_ntoa(err->src_addr));
	break;
    case 'I':
	if (err->host) {
	    memBufPrintf(&mb, "%s", err->host);
	} else
	    p = "[unknown]";
	break;
    case 'L':
	if (Config.errHtmlText) {
	    memBufPrintf(&mb, "%s", Config.errHtmlText);
	} else
	    p = "[not available]";
	break;
    case 'M':
	p = r ? RequestMethodStr[r->method] : "[unkown method]";
	break;
    case 'p':
	if (r) {
	    memBufPrintf(&mb, "%d", (int) r->port);
	} else {
	    p = "[unknown port]";
	}
	break;
    case 'P':
	p = r ? ProtocolStr[r->protocol] : "[unkown protocol]";
	break;
    case 'R':
	if (NULL != r) {
	    Packer p;
	    memBufPrintf(&mb, "%s %s HTTP/%3.1f\n",
		RequestMethodStr[r->method],
		strLen(r->urlpath) ? strBuf(r->urlpath) : "/",
		(double) r->http_ver);
	    packerToMemInit(&p, &mb);
	    httpHeaderPackInto(&r->header, &p);
	    packerClean(&p);
	} else if (err->request_hdrs) {
	    p = err->request_hdrs;
	} else {
	    p = "[no request]";
	}
	break;
    case 's':
	p = full_appname_string;
	break;
    case 'S':
	/* signature may contain %-escapes, recursion */
	if (err->page_id != ERR_SQUID_SIGNATURE) {
	    const int saved_id = err->page_id;
	    MemBuf sign_mb;
	    err->page_id = ERR_SQUID_SIGNATURE;
	    sign_mb = errorBuildContent(err);
	    memBufPrintf(&mb, "%s", sign_mb.buf);
	    memBufClean(&sign_mb);
	    err->page_id = saved_id;
	} else {
	    /* wow, somebody put %S into ERR_SIGNATURE, stop recursion */
	    p = "[%S]";
	}
	break;
    case 't':
	memBufPrintf(&mb, "%s", mkhttpdlogtime(&squid_curtime));
	break;
    case 'T':
	memBufPrintf(&mb, "%s", mkrfc1123(squid_curtime));
	break;
    case 'U':
	p = r ? urlCanonicalClean(r) : err->url ? err->url : "[no URL]";
	break;
    case 'w':
	if (Config.adminEmail)
	    memBufPrintf(&mb, "%s", Config.adminEmail);
	else
	    p = "[unknown]";
	break;
    case 'z':
	if (err->dnsserver_msg)
	    p = err->dnsserver_msg;
	else
	    p = "[unknown]";
	break;
    case '%':
	p = "%";
	break;
    default:
	memBufPrintf(&mb, "%%%c", token);
	break;
    }
    if (!p)
	p = mb.buf;		/* do not use mb after this assignment! */
    assert(p);
    debug(4, 3) ("errorConvert: %%%c --> '%s'\n", token, p);
    return p;
}

/* allocates and initializes an error response */
HttpReply *
errorBuildReply(ErrorState * err)
{
    HttpReply *rep = httpReplyCreate();
    MemBuf content = errorBuildContent(err);
    /* no LMT for error pages; error pages expire immediately */
    httpReplySetHeaders(rep, 1.0, err->http_status, NULL, "text/html", content.size, 0, squid_curtime);
    /*
     * include some information for downstream caches. Implicit
     * replaceable content. This isn't quite sufficient. xerrno is not
     * necessarily meaningful to another system, so we really should
     * expand it. Additionally, we should identify ourselves. Someone
     * might want to know. Someone _will_ want to know OTOH, the first
     * X-CACHE-MISS entry should tell us who.
     */
    httpHeaderPutStrf(&rep->header, HDR_X_SQUID_ERROR, "%s %d",
	errorPageName(err->page_id), err->xerrno);
    httpBodySet(&rep->body, &content);
    /* do not memBufClean() the content, it was absorbed by httpBody */
    return rep;
}

static MemBuf
errorBuildContent(ErrorState * err)
{
    MemBuf content;
    const char *m;
    const char *p;
    const char *t;
    assert(err != NULL);
    assert(err->page_id > ERR_NONE && err->page_id < error_page_count);
    memBufDefInit(&content);
    m = error_text[err->page_id];
    assert(m);
    while ((p = strchr(m, '%'))) {
	memBufAppend(&content, m, p - m);	/* copy */
	t = errorConvert(*++p, err);	/* convert */
	memBufPrintf(&content, "%s", t);	/* copy */
	m = p + 1;		/* advance */
    }
    if (*m)
	memBufPrintf(&content, "%s", m);	/* copy tail */
    assert(content.size == strlen(content.buf));
    return content;
}
