

/*
 * $Id: gopher.c,v 1.150.4.3 2000/04/07 20:32:29 wessels Exp $
 *
 * DEBUG: section 10    Gopher
 * AUTHOR: Harvest Derived
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

#include "squid.h"

/* gopher type code from rfc. Anawat. */
#define GOPHER_FILE         '0'
#define GOPHER_DIRECTORY    '1'
#define GOPHER_CSO          '2'
#define GOPHER_ERROR        '3'
#define GOPHER_MACBINHEX    '4'
#define GOPHER_DOSBIN       '5'
#define GOPHER_UUENCODED    '6'
#define GOPHER_INDEX        '7'
#define GOPHER_TELNET       '8'
#define GOPHER_BIN          '9'
#define GOPHER_REDUNT       '+'
#define GOPHER_3270         'T'
#define GOPHER_GIF          'g'
#define GOPHER_IMAGE        'I'

#define GOPHER_HTML         'h'	/* HTML */
#define GOPHER_INFO         'i'
#define GOPHER_WWW          'w'	/* W3 address */
#define GOPHER_SOUND        's'

#define GOPHER_PLUS_IMAGE   ':'
#define GOPHER_PLUS_MOVIE   ';'
#define GOPHER_PLUS_SOUND   '<'

#define GOPHER_PORT         70

#define TAB                 '\t'
#define TEMP_BUF_SIZE       4096
#define MAX_CSO_RESULT      1024

typedef struct gopher_ds {
    StoreEntry *entry;
    char host[SQUIDHOSTNAMELEN + 1];
    enum {
	NORMAL,
	HTML_DIR,
	HTML_INDEX_RESULT,
	HTML_CSO_RESULT,
	HTML_INDEX_PAGE,
	HTML_CSO_PAGE
    } conversion;
    int HTML_header_added;
    int port;
    char type_id;
    char request[MAX_URL];
    int data_in;
    int cso_recno;
    int len;
    char *buf;			/* pts to a 4k page */
    int fd;
    FwdState *fwdState;
} GopherStateData;

static PF gopherStateFree;
static void gopher_mime_content(MemBuf * mb, const char *name, const char *def);
static void gopherMimeCreate(GopherStateData *);
static int gopher_url_parser(const char *url,
    char *host,
    int *port,
    char *type_id,
    char *request);
static void gopherEndHTML(GopherStateData *);
static void gopherToHTML(GopherStateData *, char *inbuf, int len);
static PF gopherTimeout;
static PF gopherReadReply;
static CWCB gopherSendComplete;
static PF gopherSendRequest;
static GopherStateData *CreateGopherStateData(void);

static char def_gopher_bin[] = "www/unknown";
static char def_gopher_text[] = "text/plain";

static void
gopherStateFree(int fdnotused, void *data)
{
    GopherStateData *gopherState = data;
    if (gopherState == NULL)
	return;
    if (gopherState->entry) {
	storeUnlockObject(gopherState->entry);
    }
    memFree(gopherState->buf, MEM_4K_BUF);
    gopherState->buf = NULL;
    cbdataFree(gopherState);
}


/* figure out content type from file extension */
static void
gopher_mime_content(MemBuf * mb, const char *name, const char *def_ctype)
{
    char *ctype = mimeGetContentType(name);
    char *cenc = mimeGetContentEncoding(name);
    if (cenc)
	memBufPrintf(mb, "Content-Encoding: %s\r\n", cenc);
    memBufPrintf(mb, "Content-Type: %s\r\n",
	ctype ? ctype : def_ctype);
}



/* create MIME Header for Gopher Data */
static void
gopherMimeCreate(GopherStateData * gopherState)
{
    MemBuf mb;

    memBufDefInit(&mb);

    memBufPrintf(&mb,
	"HTTP/1.0 200 OK Gatewaying\r\n"
	"Server: Squid/%s\r\n"
	"Date: %s\r\n"
	"MIME-version: 1.0\r\n",
	version_string, mkrfc1123(squid_curtime));

    switch (gopherState->type_id) {

    case GOPHER_DIRECTORY:
    case GOPHER_INDEX:
    case GOPHER_HTML:
    case GOPHER_WWW:
    case GOPHER_CSO:
	memBufPrintf(&mb, "Content-Type: text/html\r\n");
	break;
    case GOPHER_GIF:
    case GOPHER_IMAGE:
    case GOPHER_PLUS_IMAGE:
	memBufPrintf(&mb, "Content-Type: image/gif\r\n");
	break;
    case GOPHER_SOUND:
    case GOPHER_PLUS_SOUND:
	memBufPrintf(&mb, "Content-Type: audio/basic\r\n");
	break;
    case GOPHER_PLUS_MOVIE:
	memBufPrintf(&mb, "Content-Type: video/mpeg\r\n");
	break;
    case GOPHER_MACBINHEX:
    case GOPHER_DOSBIN:
    case GOPHER_UUENCODED:
    case GOPHER_BIN:
	/* Rightnow We have no idea what it is. */
	gopher_mime_content(&mb, gopherState->request, def_gopher_bin);
	break;
    case GOPHER_FILE:
    default:
	gopher_mime_content(&mb, gopherState->request, def_gopher_text);
	break;
    }
    memBufPrintf(&mb, "\r\n");
    EBIT_CLR(gopherState->entry->flags, ENTRY_FWD_HDR_WAIT);
    storeAppend(gopherState->entry, mb.buf, mb.size);
    memBufClean(&mb);
}

/* Parse a gopher url into components.  By Anawat. */
static int
gopher_url_parser(const char *url, char *host, int *port, char *type_id, char *request)
{
    LOCAL_ARRAY(char, proto, MAX_URL);
    LOCAL_ARRAY(char, hostbuf, MAX_URL);
    int t;

    proto[0] = hostbuf[0] = '\0';
    host[0] = request[0] = '\0';
    (*port) = 0;
    (*type_id) = 0;

    t = sscanf(url,
#if defined(__QNX__)
	"%[abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ]://%[^/]/%c%s",
#else
	"%[a-zA-Z]://%[^/]/%c%s",
#endif
	proto, hostbuf, type_id, request);
    if ((t < 2) || strcasecmp(proto, "gopher")) {
	return -1;
    } else if (t == 2) {
	(*type_id) = GOPHER_DIRECTORY;
	request[0] = '\0';
    } else if (t == 3) {
	request[0] = '\0';
    } else {
	/* convert %xx to char */
	url_convert_hex(request, 0);
    }

    host[0] = '\0';
    if (sscanf(hostbuf, "%[^:]:%d", host, port) < 2)
	(*port) = GOPHER_PORT;

    return 0;
}

int
gopherCachable(const char *url)
{
    GopherStateData *gopherState = NULL;
    int cachable = 1;
    /* use as temp data structure to parse gopher URL */
    gopherState = CreateGopherStateData();
    /* parse to see type */
    gopher_url_parser(url,
	gopherState->host,
	&gopherState->port,
	&gopherState->type_id,
	gopherState->request);
    switch (gopherState->type_id) {
    case GOPHER_INDEX:
    case GOPHER_CSO:
    case GOPHER_TELNET:
    case GOPHER_3270:
	cachable = 0;
	break;
    default:
	cachable = 1;
    }
    gopherStateFree(-1, gopherState);
    return cachable;
}

static void
gopherEndHTML(GopherStateData * gopherState)
{
    if (!gopherState->data_in)
	storeAppendPrintf(gopherState->entry,
	    "<HTML><HEAD><TITLE>Server Return Nothing.</TITLE>\n"
	    "</HEAD><BODY><HR><H1>Server Return Nothing.</H1></BODY></HTML>\n");
}


/* Convert Gopher to HTML */
/* Borrow part of code from libwww2 came with Mosaic distribution */
static void
gopherToHTML(GopherStateData * gopherState, char *inbuf, int len)
{
    char *pos = inbuf;
    char *lpos = NULL;
    char *tline = NULL;
    LOCAL_ARRAY(char, line, TEMP_BUF_SIZE);
    LOCAL_ARRAY(char, tmpbuf, TEMP_BUF_SIZE);
    LOCAL_ARRAY(char, outbuf, TEMP_BUF_SIZE << 4);
    char *name = NULL;
    char *selector = NULL;
    char *host = NULL;
    char *port = NULL;
    char *escaped_selector = NULL;
    const char *icon_url = NULL;
    char gtype;
    StoreEntry *entry = NULL;

    memset(outbuf, '\0', TEMP_BUF_SIZE << 4);
    memset(tmpbuf, '\0', TEMP_BUF_SIZE);
    memset(line, '\0', TEMP_BUF_SIZE);

    entry = gopherState->entry;

    if (gopherState->conversion == HTML_INDEX_PAGE) {
	storeAppendPrintf(entry,
	    "<HTML><HEAD><TITLE>Gopher Index %s</TITLE></HEAD>\n"
	    "<BODY><H1>%s<BR>Gopher Search</H1>\n"
	    "<p>This is a searchable Gopher index. Use the search\n"
	    "function of your browser to enter search terms.\n"
	    "<ISINDEX></BODY></HTML>\n",
	    storeUrl(entry), storeUrl(entry));
	/* now let start sending stuff to client */
	storeBufferFlush(entry);
	gopherState->data_in = 1;

	return;
    }
    if (gopherState->conversion == HTML_CSO_PAGE) {
	storeAppendPrintf(entry,
	    "<HTML><HEAD><TITLE>CSO Search of %s</TITLE></HEAD>\n"
	    "<BODY><H1>%s<BR>CSO Search</H1>\n"
	    "<P>A CSO database usually contains a phonebook or\n"
	    "directory.  Use the search function of your browser to enter\n"
	    "search terms.</P><ISINDEX></BODY></HTML>\n",
	    storeUrl(entry), storeUrl(entry));
	/* now let start sending stuff to client */
	storeBufferFlush(entry);
	gopherState->data_in = 1;

	return;
    }
    inbuf[len] = '\0';

    if (!gopherState->HTML_header_added) {
	if (gopherState->conversion == HTML_CSO_RESULT)
	    strcat(outbuf, "<HTML><HEAD><TITLE>CSO Searchs Result</TITLE></HEAD>\n"
		"<BODY><H1>CSO Searchs Result</H1>\n<PRE>\n");
	else
	    strcat(outbuf, "<HTML><HEAD><TITLE>Gopher Menu</TITLE></HEAD>\n"
		"<BODY><H1>Gopher Menu</H1>\n<PRE>\n");
	gopherState->HTML_header_added = 1;
    }
    while ((pos != NULL) && (pos < inbuf + len)) {

	if (gopherState->len != 0) {
	    /* there is something left from last tx. */
	    xstrncpy(line, gopherState->buf, gopherState->len);
	    lpos = (char *) memccpy(line + gopherState->len, inbuf, '\n', len);
	    if (lpos)
		*lpos = '\0';
	    else {
		/* there is no complete line in inbuf */
		/* copy it to temp buffer */
		if (gopherState->len + len > TEMP_BUF_SIZE) {
		    debug(10, 1) ("GopherHTML: Buffer overflow. Lost some data on URL: %s\n",
			storeUrl(entry));
		    len = TEMP_BUF_SIZE - gopherState->len;
		}
		xmemcpy(gopherState->buf + gopherState->len, inbuf, len);
		gopherState->len += len;
		return;
	    }

	    /* skip one line */
	    pos = (char *) memchr(pos, '\n', len);
	    if (pos)
		pos++;

	    /* we're done with the remain from last tx. */
	    gopherState->len = 0;
	    *(gopherState->buf) = '\0';
	} else {

	    lpos = (char *) memccpy(line, pos, '\n', len - (pos - inbuf));
	    if (lpos)
		*lpos = '\0';
	    else {
		/* there is no complete line in inbuf */
		/* copy it to temp buffer */
		if ((len - (pos - inbuf)) > TEMP_BUF_SIZE) {
		    debug(10, 1) ("GopherHTML: Buffer overflow. Lost some data on URL: %s\n",
			storeUrl(entry));
		    len = TEMP_BUF_SIZE;
		}
		if (len > (pos - inbuf)) {
		    xmemcpy(gopherState->buf, pos, len - (pos - inbuf));
		    gopherState->len = len - (pos - inbuf);
		}
		break;
	    }

	    /* skip one line */
	    pos = (char *) memchr(pos, '\n', len);
	    if (pos)
		pos++;

	}

	/* at this point. We should have one line in buffer to process */

	if (*line == '.') {
	    /* skip it */
	    memset(line, '\0', TEMP_BUF_SIZE);
	    continue;
	}
	switch (gopherState->conversion) {

	case HTML_INDEX_RESULT:
	case HTML_DIR:{
		tline = line;
		gtype = *tline++;
		name = tline;
		selector = strchr(tline, TAB);
		if (selector) {
		    *selector++ = '\0';
		    host = strchr(selector, TAB);
		    if (host) {
			*host++ = '\0';
			port = strchr(host, TAB);
			if (port) {
			    char *junk;
			    port[0] = ':';
			    junk = strchr(host, TAB);
			    if (junk)
				*junk++ = 0;	/* Chop port */
			    else {
				junk = strchr(host, '\r');
				if (junk)
				    *junk++ = 0;	/* Chop port */
				else {
				    junk = strchr(host, '\n');
				    if (junk)
					*junk++ = 0;	/* Chop port */
				}
			    }
			    if ((port[1] == '0') && (!port[2]))
				port[0] = 0;	/* 0 means none */
			}
			/* escape a selector here */
			escaped_selector = xstrdup(rfc1738_escape_part(selector));

			switch (gtype) {
			case GOPHER_DIRECTORY:
			    icon_url = mimeGetIconURL("internal-menu");
			    break;
			case GOPHER_FILE:
			    icon_url = mimeGetIconURL("internal-text");
			    break;
			case GOPHER_INDEX:
			case GOPHER_CSO:
			    icon_url = mimeGetIconURL("internal-index");
			    break;
			case GOPHER_IMAGE:
			case GOPHER_GIF:
			case GOPHER_PLUS_IMAGE:
			    icon_url = mimeGetIconURL("internal-image");
			    break;
			case GOPHER_SOUND:
			case GOPHER_PLUS_SOUND:
			    icon_url = mimeGetIconURL("internal-sound");
			    break;
			case GOPHER_PLUS_MOVIE:
			    icon_url = mimeGetIconURL("internal-movie");
			    break;
			case GOPHER_TELNET:
			case GOPHER_3270:
			    icon_url = mimeGetIconURL("internal-telnet");
			    break;
			case GOPHER_BIN:
			case GOPHER_MACBINHEX:
			case GOPHER_DOSBIN:
			case GOPHER_UUENCODED:
			    icon_url = mimeGetIconURL("internal-binary");
			    break;
			default:
			    icon_url = mimeGetIconURL("internal-unknown");
			    break;
			}


			memset(tmpbuf, '\0', TEMP_BUF_SIZE);
			if ((gtype == GOPHER_TELNET) || (gtype == GOPHER_3270)) {
			    if (strlen(escaped_selector) != 0)
				snprintf(tmpbuf, TEMP_BUF_SIZE, "<IMG BORDER=0 SRC=\"%s\"> <A HREF=\"telnet://%s@%s/\">%s</A>\n",
				    icon_url, escaped_selector, host, name);
			    else
				snprintf(tmpbuf, TEMP_BUF_SIZE, "<IMG BORDER=0 SRC=\"%s\"> <A HREF=\"telnet://%s/\">%s</A>\n",
				    icon_url, host, name);

			} else {
			    snprintf(tmpbuf, TEMP_BUF_SIZE, "<IMG BORDER=0 SRC=\"%s\"> <A HREF=\"gopher://%s/%c%s\">%s</A>\n",
				icon_url, host, gtype, escaped_selector, name);
			}
			safe_free(escaped_selector);
			strcat(outbuf, tmpbuf);
			gopherState->data_in = 1;
		    } else {
			memset(line, '\0', TEMP_BUF_SIZE);
			continue;
		    }
		} else {
		    memset(line, '\0', TEMP_BUF_SIZE);
		    continue;
		}
		break;
	    }			/* HTML_DIR, HTML_INDEX_RESULT */


	case HTML_CSO_RESULT:{
		int t;
		int code;
		int recno;
		LOCAL_ARRAY(char, result, MAX_CSO_RESULT);

		tline = line;

		if (tline[0] == '-') {
		    t = sscanf(tline, "-%d:%d:%[^\n]", &code, &recno, result);
		    if (t < 3)
			break;

		    if (code != 200)
			break;

		    if (gopherState->cso_recno != recno) {
			snprintf(tmpbuf, TEMP_BUF_SIZE, "</PRE><HR><H2>Record# %d<br><i>%s</i></H2>\n<PRE>", recno, result);
			gopherState->cso_recno = recno;
		    } else {
			snprintf(tmpbuf, TEMP_BUF_SIZE, "%s\n", result);
		    }
		    strcat(outbuf, tmpbuf);
		    gopherState->data_in = 1;
		    break;
		} else {
		    /* handle some error codes */
		    t = sscanf(tline, "%d:%[^\n]", &code, result);

		    if (t < 2)
			break;

		    switch (code) {

		    case 200:{
			    /* OK */
			    /* Do nothing here */
			    break;
			}

		    case 102:	/* Number of matches */
		    case 501:	/* No Match */
		    case 502:	/* Too Many Matches */
			{
			    /* Print the message the server returns */
			    snprintf(tmpbuf, TEMP_BUF_SIZE, "</PRE><HR><H2>%s</H2>\n<PRE>", result);
			    strcat(outbuf, tmpbuf);
			    gopherState->data_in = 1;
			    break;
			}


		    }
		}

	    }			/* HTML_CSO_RESULT */
	default:
	    break;		/* do nothing */

	}			/* switch */

    }				/* while loop */

    if ((int) strlen(outbuf) > 0) {
	storeAppend(entry, outbuf, strlen(outbuf));
	/* now let start sending stuff to client */
	storeBufferFlush(entry);
    }
    return;
}

static void
gopherTimeout(int fd, void *data)
{
    GopherStateData *gopherState = data;
    StoreEntry *entry = gopherState->entry;
    debug(10, 4) ("gopherTimeout: FD %d: '%s'\n", fd, storeUrl(entry));
    if (entry->store_status == STORE_PENDING) {
	if (entry->mem_obj->inmem_hi == 0) {
	    fwdFail(gopherState->fwdState,
		errorCon(ERR_READ_TIMEOUT, HTTP_GATEWAY_TIMEOUT));
	}
    }
    comm_close(fd);
}

/* This will be called when data is ready to be read from fd.  Read until
 * error or connection closed. */
static void
gopherReadReply(int fd, void *data)
{
    GopherStateData *gopherState = data;
    StoreEntry *entry = gopherState->entry;
    char *buf = NULL;
    int len;
    int clen;
    int bin;
    size_t read_sz;
#if DELAY_POOLS
    delay_id delay_id = delayMostBytesAllowed(entry->mem_obj);
#endif
    if (EBIT_TEST(entry->flags, ENTRY_ABORTED)) {
	comm_close(fd);
	return;
    }
    errno = 0;
    buf = memAllocate(MEM_4K_BUF);
    read_sz = 4096 - 1;		/* leave room for termination */
#if DELAY_POOLS
    read_sz = delayBytesWanted(delay_id, 1, read_sz);
#endif
    /* leave one space for \0 in gopherToHTML */
    Counter.syscalls.sock.reads++;
    len = read(fd, buf, read_sz);
    if (len > 0) {
	fd_bytes(fd, len, FD_READ);
#if DELAY_POOLS
	delayBytesIn(delay_id, len);
#endif
	kb_incr(&Counter.server.all.kbytes_in, len);
	kb_incr(&Counter.server.other.kbytes_in, len);
    }
    debug(10, 5) ("gopherReadReply: FD %d read len=%d\n", fd, len);
    if (len > 0) {
	commSetTimeout(fd, Config.Timeout.read, NULL, NULL);
	IOStats.Gopher.reads++;
	for (clen = len - 1, bin = 0; clen; bin++)
	    clen >>= 1;
	IOStats.Gopher.read_hist[bin]++;
    }
    if (len < 0) {
	debug(50, 1) ("gopherReadReply: error reading: %s\n", xstrerror());
	if (ignoreErrno(errno)) {
	    commSetSelect(fd, COMM_SELECT_READ, gopherReadReply, data, 0);
	} else if (entry->mem_obj->inmem_hi == 0) {
	    ErrorState *err;
	    err = errorCon(ERR_READ_ERROR, HTTP_INTERNAL_SERVER_ERROR);
	    err->xerrno = errno;
	    err->url = xstrdup(storeUrl(entry));
	    errorAppendEntry(entry, err);
	    comm_close(fd);
	} else {
	    comm_close(fd);
	}
    } else if (len == 0 && entry->mem_obj->inmem_hi == 0) {
	ErrorState *err;
	err = errorCon(ERR_ZERO_SIZE_OBJECT, HTTP_SERVICE_UNAVAILABLE);
	err->xerrno = errno;
	err->url = xstrdup(gopherState->request);
	errorAppendEntry(entry, err);
	comm_close(fd);
    } else if (len == 0) {
	/* Connection closed; retrieval done. */
	/* flush the rest of data in temp buf if there is one. */
	if (gopherState->conversion != NORMAL)
	    gopherEndHTML(data);
	storeTimestampsSet(entry);
	storeBufferFlush(entry);
	fwdComplete(gopherState->fwdState);
	comm_close(fd);
    } else {
	if (gopherState->conversion != NORMAL) {
	    gopherToHTML(data, buf, len);
	} else {
	    storeAppend(entry, buf, len);
	}
	commSetSelect(fd,
	    COMM_SELECT_READ,
	    gopherReadReply,
	    data, 0);
    }
    memFree(buf, MEM_4K_BUF);
    return;
}

/* This will be called when request write is complete. Schedule read of
 * reply. */
static void
gopherSendComplete(int fd, char *buf, size_t size, int errflag, void *data)
{
    GopherStateData *gopherState = (GopherStateData *) data;
    StoreEntry *entry = gopherState->entry;
    debug(10, 5) ("gopherSendComplete: FD %d size: %d errflag: %d\n",
	fd, size, errflag);
    if (size > 0) {
	fd_bytes(fd, size, FD_WRITE);
	kb_incr(&Counter.server.all.kbytes_out, size);
	kb_incr(&Counter.server.other.kbytes_out, size);
    }
    if (errflag) {
	ErrorState *err;
	err = errorCon(ERR_CONNECT_FAIL, HTTP_SERVICE_UNAVAILABLE);
	err->xerrno = errno;
	err->host = xstrdup(gopherState->host);
	err->port = gopherState->port;
	err->url = xstrdup(storeUrl(entry));
	errorAppendEntry(entry, err);
	comm_close(fd);
	if (buf)
	    memFree(buf, MEM_4K_BUF);	/* Allocated by gopherSendRequest. */
	return;
    }
    /* 
     * OK. We successfully reach remote site.  Start MIME typing
     * stuff.  Do it anyway even though request is not HTML type.
     */
    gopherMimeCreate(gopherState);
    switch (gopherState->type_id) {
    case GOPHER_DIRECTORY:
	/* we got to convert it first */
	storeBuffer(entry);
	gopherState->conversion = HTML_DIR;
	gopherState->HTML_header_added = 0;
	break;
    case GOPHER_INDEX:
	/* we got to convert it first */
	storeBuffer(entry);
	gopherState->conversion = HTML_INDEX_RESULT;
	gopherState->HTML_header_added = 0;
	break;
    case GOPHER_CSO:
	/* we got to convert it first */
	storeBuffer(entry);
	gopherState->conversion = HTML_CSO_RESULT;
	gopherState->cso_recno = 0;
	gopherState->HTML_header_added = 0;
	break;
    default:
	gopherState->conversion = NORMAL;
    }
    /* Schedule read reply. */
    commSetSelect(fd, COMM_SELECT_READ, gopherReadReply, gopherState, 0);
    commSetDefer(fd, fwdCheckDeferRead, entry);
    if (buf)
	memFree(buf, MEM_4K_BUF);	/* Allocated by gopherSendRequest. */
}

/* This will be called when connect completes. Write request. */
static void
gopherSendRequest(int fd, void *data)
{
    GopherStateData *gopherState = data;
    LOCAL_ARRAY(char, query, MAX_URL);
    char *buf = memAllocate(MEM_4K_BUF);
    char *t;
    if (gopherState->type_id == GOPHER_CSO) {
	sscanf(gopherState->request, "?%s", query);
	snprintf(buf, 4096, "query %s\r\nquit\r\n", query);
    } else if (gopherState->type_id == GOPHER_INDEX) {
	if ((t = strchr(gopherState->request, '?')))
	    *t = '\t';
	snprintf(buf, 4096, "%s\r\n", gopherState->request);
    } else {
	snprintf(buf, 4096, "%s\r\n", gopherState->request);
    }
    debug(10, 5) ("gopherSendRequest: FD %d\n", fd);
    comm_write(fd,
	buf,
	strlen(buf),
	gopherSendComplete,
	data,
	memFree4K);
    if (EBIT_TEST(gopherState->entry->flags, ENTRY_CACHABLE))
	storeSetPublicKey(gopherState->entry);	/* Make it public */
}

void
gopherStart(FwdState * fwdState)
{
    int fd = fwdState->server_fd;
    StoreEntry *entry = fwdState->entry;
    GopherStateData *gopherState = CreateGopherStateData();
    storeLockObject(entry);
    gopherState->entry = entry;
    debug(10, 3) ("gopherStart: %s\n", storeUrl(entry));
    Counter.server.all.requests++;
    Counter.server.other.requests++;
    /* Parse url. */
    if (gopher_url_parser(storeUrl(entry), gopherState->host, &gopherState->port,
	    &gopherState->type_id, gopherState->request)) {
	ErrorState *err;
	err = errorCon(ERR_INVALID_URL, HTTP_BAD_REQUEST);
	err->url = xstrdup(storeUrl(entry));
	errorAppendEntry(entry, err);
	gopherStateFree(-1, gopherState);
	return;
    }
    comm_add_close_handler(fd, gopherStateFree, gopherState);
    if (((gopherState->type_id == GOPHER_INDEX) || (gopherState->type_id == GOPHER_CSO))
	&& (strchr(gopherState->request, '?') == NULL)) {
	/* Index URL without query word */
	/* We have to generate search page back to client. No need for connection */
	gopherMimeCreate(gopherState);
	if (gopherState->type_id == GOPHER_INDEX) {
	    gopherState->conversion = HTML_INDEX_PAGE;
	} else {
	    if (gopherState->type_id == GOPHER_CSO) {
		gopherState->conversion = HTML_CSO_PAGE;
	    } else {
		gopherState->conversion = HTML_INDEX_PAGE;
	    }
	}
	gopherToHTML(gopherState, (char *) NULL, 0);
	fwdComplete(fwdState);
	comm_close(fd);
	return;
    }
    gopherState->fd = fd;
    gopherState->fwdState = fwdState;
    commSetSelect(fd, COMM_SELECT_WRITE, gopherSendRequest, gopherState, 0);
    commSetTimeout(fd, Config.Timeout.read, gopherTimeout, gopherState);
}

static GopherStateData *
CreateGopherStateData(void)
{
    GopherStateData *gd = xcalloc(1, sizeof(GopherStateData));
    cbdataAdd(gd, cbdataXfree, 0);
    gd->buf = memAllocate(MEM_4K_BUF);
    return (gd);
}
