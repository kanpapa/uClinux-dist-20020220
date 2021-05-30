/*
 * $Id: cf_gen.c,v 1.32.2.1 2000/02/09 23:29:53 wessels Exp $
 *
 * DEBUG: none
 * AUTHOR: Max Okumoto
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

/*****************************************************************************
 * Abstract:	This program parses the input file and generates code and
 *		files used to configure the variables in squid.
 *		(ie it creates the squid.conf file from the cf.data file)
 *
 *		The output files are as follows:
 *		cf_parser.c - this file contains, default_all() which
 *			  initializes variables with the default
 *			  values, parse_line() that parses line from
 *			  squid.conf, dump_config that dumps the
 *			  current the values of the variables.
 *		squid.conf - default configuration file given to the server
 *			 administrator.
 *****************************************************************************/

#include "config.h"

#if HAVE_STDIO_H
#include <stdio.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_CTYPE_H
#include <ctype.h>
#endif
#if HAVE_ASSERT_H
#include <assert.h>
#endif

#include "util.h"

#define MAX_LINE	1024	/* longest configuration line */
#define _PATH_PARSER		"cf_parser.c"
#define _PATH_SQUID_CONF	"squid.conf"

enum State {
    sSTART,
    s1,
    sDOC,
    sNOCOMMENT,
    sEXIT
};

typedef struct Line {
    char *data;
    struct Line *next;
} Line;

typedef struct Entry {
    char *name;
    char *type;
    char *loc;
    char *default_value;
    char *default_if_none;
    char *comment;
    char *ifdef;
    Line *doc;
    Line *nocomment;
    struct Entry *next;
} Entry;


static const char WS[] = " \t";
static int gen_default(Entry *, FILE *);
static void gen_parse(Entry *, FILE *);
static void gen_dump(Entry *, FILE *);
static void gen_free(Entry *, FILE *);
static void gen_conf(Entry *, FILE *);
static void gen_default_if_none(Entry *, FILE *);

int
main(int argc, char *argv[])
{
    FILE *fp;
    char *input_filename = argv[1];
    char *output_filename = _PATH_PARSER;
    char *conf_filename = _PATH_SQUID_CONF;
    int linenum = 0;
    Entry *entries = NULL;
    Entry *curr = NULL;
    enum State state;
    int rc = 0;
    char *ptr = NULL;
#ifdef _SQUID_OS2_
    const char *rmode = "rt";
#else
    const char *rmode = "r";
#endif

    /*-------------------------------------------------------------------*
     * Parse input file
     *-------------------------------------------------------------------*/

    /* Open input file */
    if ((fp = fopen(input_filename, rmode)) == NULL) {
	perror(input_filename);
	exit(1);
    }
    state = sSTART;
    while (feof(fp) == 0 && state != sEXIT) {
	char buff[MAX_LINE];
	char *t;
	if (NULL == fgets(buff, MAX_LINE, fp))
	    break;
	linenum++;
	if ((t = strchr(buff, '\n')))
	    *t = '\0';
	switch (state) {
	case sSTART:
	    if ((strlen(buff) == 0) || (!strncmp(buff, "#", 1))) {
		/* ignore empty and comment lines */
		(void) 0;
	    } else if (!strncmp(buff, "NAME:", 5)) {
		char *name;
		if ((name = strtok(buff + 5, WS)) == NULL) {
		    printf("Error in input file\n");
		    exit(1);
		}
		curr = calloc(1, sizeof(Entry));
		curr->name = xstrdup(name);
		state = s1;
	    } else if (!strcmp(buff, "EOF")) {
		state = sEXIT;
	    } else if (!strcmp(buff, "COMMENT_START")) {
		curr = calloc(1, sizeof(Entry));
		curr->name = xstrdup("comment");
		curr->loc = xstrdup("none");
		state = sDOC;
	    } else {
		printf("Error on line %d\n", linenum);
		printf("--> %s\n", buff);
		exit(1);
	    }
	    break;

	case s1:
	    if ((strlen(buff) == 0) || (!strncmp(buff, "#", 1))) {
		/* ignore empty and comment lines */
		(void) 0;
	    } else if (!strncmp(buff, "COMMENT:", 8)) {
		ptr = buff + 8;
		while (xisspace(*ptr))
		    ptr++;
		curr->comment = xstrdup(ptr);
	    } else if (!strncmp(buff, "DEFAULT:", 8)) {
		ptr = buff + 8;
		while (xisspace(*ptr))
		    ptr++;
		curr->default_value = xstrdup(ptr);
	    } else if (!strncmp(buff, "DEFAULT_IF_NONE:", 16)) {
		ptr = buff + 16;
		while (xisspace(*ptr))
		    ptr++;
		curr->default_if_none = xstrdup(ptr);
	    } else if (!strncmp(buff, "LOC:", 4)) {
		if ((ptr = strtok(buff + 4, WS)) == NULL) {
		    printf("Error on line %d\n", linenum);
		    exit(1);
		}
		curr->loc = xstrdup(ptr);
	    } else if (!strncmp(buff, "TYPE:", 5)) {
		if ((ptr = strtok(buff + 5, WS)) == NULL) {
		    printf("Error on line %d\n", linenum);
		    exit(1);
		}
		curr->type = xstrdup(ptr);
	    } else if (!strncmp(buff, "IFDEF:", 6)) {
		if ((ptr = strtok(buff + 6, WS)) == NULL) {
		    printf("Error on line %d\n", linenum);
		    exit(1);
		}
		curr->ifdef = xstrdup(ptr);
	    } else if (!strcmp(buff, "DOC_START")) {
		state = sDOC;
	    } else if (!strcmp(buff, "DOC_NONE")) {
		/* add to list of entries */
		curr->next = entries;
		entries = curr;
		state = sSTART;
	    } else {
		printf("Error on line %d\n", linenum);
		exit(1);
	    }
	    break;

	case sDOC:
	    if (!strcmp(buff, "DOC_END") || !strcmp(buff, "COMMENT_END")) {
		Line *head = NULL;
		Line *line = curr->doc;
		/* reverse order of doc lines */
		while (line != NULL) {
		    Line *tmp;
		    tmp = line->next;
		    line->next = head;
		    head = line;
		    line = tmp;
		}
		curr->doc = head;
		/* add to list of entries */
		curr->next = entries;
		entries = curr;
		state = sSTART;
	    } else if (!strcmp(buff, "NOCOMMENT_START")) {
		state = sNOCOMMENT;
	    } else {
		Line *line = calloc(1, sizeof(Line));
		line->data = xstrdup(buff);
		line->next = curr->doc;
		curr->doc = line;
	    }
	    break;

	case sNOCOMMENT:
	    if (!strcmp(buff, "NOCOMMENT_END")) {
		Line *head = NULL;
		Line *line = curr->nocomment;
		/* reverse order of lines */
		while (line != NULL) {
		    Line *tmp;
		    tmp = line->next;
		    line->next = head;
		    head = line;
		    line = tmp;
		}
		curr->nocomment = head;
		state = sDOC;
	    } else {
		Line *line = calloc(1, sizeof(Line));
		line->data = xstrdup(buff);
		line->next = curr->nocomment;
		curr->nocomment = line;
	    }
	    break;

	case sEXIT:
	    assert(0);		/* should never get here */
	    break;
	}
    }
    if (state != sEXIT) {
	printf("Error unexpected EOF\n");
	exit(1);
    } else {
	/* reverse order of entries */
	Entry *head = NULL;

	while (entries != NULL) {
	    Entry *tmp;

	    tmp = entries->next;
	    entries->next = head;
	    head = entries;
	    entries = tmp;
	}
	entries = head;
    }
    fclose(fp);

    /*-------------------------------------------------------------------*
     * Generate default_all()
     * Generate parse_line()
     * Generate dump_config()
     * Generate free_all()
     * Generate example squid.conf file
     *-------------------------------------------------------------------*/

    /* Open output x.c file */
    if ((fp = fopen(output_filename, "w")) == NULL) {
	perror(output_filename);
	exit(1);
    }
    fprintf(fp,
	"/*\n"
	" * Generated automatically from %s by %s\n"
	" *\n"
	" * Abstract: This file contains routines used to configure the\n"
	" *           variables in the squid server.\n"
	" */\n"
	"\n",
	input_filename, argv[0]
	);
    rc = gen_default(entries, fp);
    gen_default_if_none(entries, fp);
    gen_parse(entries, fp);
    gen_dump(entries, fp);
    gen_free(entries, fp);
    fclose(fp);

    /* Open output x.conf file */
    if ((fp = fopen(conf_filename, "w")) == NULL) {
	perror(conf_filename);
	exit(1);
    }
    gen_conf(entries, fp);
    fclose(fp);

    return (rc);
}

static int
gen_default(Entry * head, FILE * fp)
{
    Entry *entry;
    int rc = 0;
    fprintf(fp,
	"static void\n"
	"default_line(const char *s)\n"
	"{\n"
	"\tLOCAL_ARRAY(char, tmp_line, BUFSIZ);\n"
	"\txstrncpy(tmp_line, s, BUFSIZ);\n"
	"\txstrncpy(config_input_line, s, BUFSIZ);\n"
	"\tconfig_lineno++;\n"
	"\tparse_line(tmp_line);\n"
	"}\n"
	);
    fprintf(fp,
	"static void\n"
	"default_all(void)\n"
	"{\n"
	"\tcfg_filename = \"Default Configuration\";\n"
	"\tconfig_lineno = 0;\n"
	);
    for (entry = head; entry != NULL; entry = entry->next) {
	assert(entry->name);
	assert(entry != entry->next);

	if (!strcmp(entry->name, "comment"))
	    continue;
	if (entry->loc == NULL) {
	    fprintf(stderr, "NO LOCATION FOR %s\n", entry->name);
	    rc |= 1;
	    continue;
	}
	if (entry->default_value == NULL) {
	    fprintf(stderr, "NO DEFAULT FOR %s\n", entry->name);
	    rc |= 1;
	    continue;
	}
	assert(entry->default_value);
	if (entry->ifdef)
	    fprintf(fp, "#if %s\n", entry->ifdef);
	if (strcmp(entry->default_value, "none") == 0) {
	    fprintf(fp, "\t/* No default for %s */\n", entry->name);
	} else {
	    fprintf(fp, "\tdefault_line(\"%s %s\");\n",
		entry->name,
		entry->default_value);
	}
	if (entry->ifdef)
	    fprintf(fp, "#endif\n");
    }
    fprintf(fp, "\tcfg_filename = NULL;\n");
    fprintf(fp, "}\n\n");
    return rc;
}

static void
gen_default_if_none(Entry * head, FILE * fp)
{
    Entry *entry;
    fprintf(fp,
	"static void\n"
	"defaults_if_none(void)\n"
	"{\n"
	);
    for (entry = head; entry != NULL; entry = entry->next) {
	assert(entry->name);
	assert(entry->loc);
	if (entry->default_if_none == NULL)
	    continue;
	if (entry->ifdef)
	    fprintf(fp, "#if %s\n", entry->ifdef);
	fprintf(fp,
	    "\tif (check_null_%s(%s))\n"
	    "\t\tdefault_line(\"%s %s\");\n",
	    entry->type,
	    entry->loc,
	    entry->name,
	    entry->default_if_none);
	if (entry->ifdef)
	    fprintf(fp, "#endif\n");
    }
    fprintf(fp, "}\n\n");
}

static void
gen_parse(Entry * head, FILE * fp)
{
    Entry *entry;

    fprintf(fp,
	"static int\n"
	"parse_line(char *buff)\n"
	"{\n"
	"\tint\tresult = 1;\n"
	"\tchar\t*token;\n"
	"\tdebug(0,10)(\"parse_line: %%s\\n\", buff);\n"
	"\tif ((token = strtok(buff, w_space)) == NULL)\n"
	"\t\t(void) 0;\t/* ignore empty lines */\n"
	);

    for (entry = head; entry != NULL; entry = entry->next) {
	if (strcmp(entry->name, "comment") == 0)
	    continue;
	if (entry->ifdef)
	    fprintf(fp, "#if %s\n", entry->ifdef);
	fprintf(fp, "\telse if (!strcmp(token, \"%s\"))\n",
	    entry->name
	    );
	assert(entry->loc);
	if (strcmp(entry->loc, "none") == 0) {
	    fprintf(fp,
		"\t\tparse_%s();\n",
		entry->type
		);
	} else {
	    fprintf(fp,
		"\t\tparse_%s(&%s);\n",
		entry->type, entry->loc
		);
	}
	if (entry->ifdef)
	    fprintf(fp, "#endif\n");
    }

    fprintf(fp,
	"\telse\n"
	"\t\tresult = 0; /* failure */\n"
	"\treturn(result);\n"
	"}\n\n"
	);
}

static void
gen_dump(Entry * head, FILE * fp)
{
    Entry *entry;
    fprintf(fp,
	"static void\n"
	"dump_config(StoreEntry *entry)\n"
	"{\n"
	);
    for (entry = head; entry != NULL; entry = entry->next) {
	assert(entry->loc);
	if (strcmp(entry->loc, "none") == 0)
	    continue;
	if (strcmp(entry->name, "comment") == 0)
	    continue;
	if (entry->ifdef)
	    fprintf(fp, "#if %s\n", entry->ifdef);
	fprintf(fp, "\tdump_%s(entry, \"%s\", %s);\n",
	    entry->type,
	    entry->name,
	    entry->loc);
	if (entry->ifdef)
	    fprintf(fp, "#endif\n");
    }
    fprintf(fp, "}\n\n");
}

static void
gen_free(Entry * head, FILE * fp)
{
    Entry *entry;
    fprintf(fp,
	"static void\n"
	"free_all(void)\n"
	"{\n"
	);
    for (entry = head; entry != NULL; entry = entry->next) {
	assert(entry->loc);
	if (strcmp(entry->loc, "none") == 0)
	    continue;
	if (strcmp(entry->name, "comment") == 0)
	    continue;
	if (entry->ifdef)
	    fprintf(fp, "#if %s\n", entry->ifdef);
	fprintf(fp, "\tfree_%s(&%s);\n", entry->type, entry->loc);
	if (entry->ifdef)
	    fprintf(fp, "#endif\n");
    }
    fprintf(fp, "}\n\n");
}

static void
gen_conf(Entry * head, FILE * fp)
{
    Entry *entry;

    for (entry = head; entry != NULL; entry = entry->next) {
	Line *line;

	if (!strcmp(entry->name, "comment"))
	    (void) 0;
	else
	    fprintf(fp, "#  TAG: %s", entry->name);
	if (entry->comment)
	    fprintf(fp, "\t%s", entry->comment);
	fprintf(fp, "\n");
	for (line = entry->doc; line != NULL; line = line->next) {
	    fprintf(fp, "#%s\n", line->data);
	}
	for (line = entry->nocomment; line != NULL; line = line->next) {
	    fprintf(fp, "%s\n", line->data);
	}
	if (entry->doc != NULL) {
	    fprintf(fp, "\n");
	}
    }
}
