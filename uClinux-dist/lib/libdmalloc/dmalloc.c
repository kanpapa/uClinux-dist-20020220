/*
 * program that handles the dmalloc variables.
 *
 * Copyright 2000 by Gray Watson
 *
 * This file is part of the dmalloc package.
 *
 * Permission to use, copy, modify, and distribute this software for
 * any purpose and without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies, and that the name of Gray Watson not be used in advertising
 * or publicity pertaining to distribution of the document or software
 * without specific, written prior permission.
 *
 * Gray Watson makes no representations about the suitability of the
 * software described herein for any purpose.  It is provided "as is"
 * without express or implied warranty.
 *
 * The author may be contacted via http://dmalloc.com/
 *
 * $Id: dmalloc.c,v 1.1 2000/11/01 01:19:03 pauli Exp $
 */

/*
 * This is the dmalloc program which is designed to enable the user to
 * easily set the environmental variables that control the dmalloc
 * library capabilities.
 */
/*
 * NOTE: all standard-output from this program is designed to be run
 * through a shell evaluation command by default.  Any messages for
 * the user should therefore be send to stderr.
 */

#include <stdio.h>				/* for stderr */

#define DMALLOC_DISABLE

#include "dmalloc_argv.h"			/* for argument processing */

#if HAVE_STRING_H
# include <string.h>
#endif
#if HAVE_STDLIB_H
# include <stdlib.h>
#endif

#include "conf.h"
#include "dmalloc.h"

#include "compat.h"
#include "debug_tok.h"
#include "debug_val.h"
#include "env.h"
#include "error_str.h"
#include "error_val.h"
#include "dmalloc_loc.h"
#include "version.h"

#if INCLUDE_RCS_IDS
#ifdef __GNUC__
#ident "$Id: dmalloc.c,v 1.1 2000/11/01 01:19:03 pauli Exp $";
#else
static	char	*rcs_id =
  "$Id: dmalloc.c,v 1.1 2000/11/01 01:19:03 pauli Exp $";
#endif
#endif

#define HOME_ENVIRON	"HOME"			/* home directory */
#define SHELL_ENVIRON	"SHELL"			/* for the type of shell */
#define DEFAULT_CONFIG	".dmallocrc"		/* default config file */
#define TOKENIZE_EQUALS	" \t="			/* for tag lines */
#define TOKENIZE_CHARS	" \t,"			/* for tag lines */

#define DEBUG_ARG		'd'		/* debug argument */
#define INTERVAL_ARG		'i'		/* interval argument */
#define THREAD_LOCK_ON_ARG	'o'		/* lock-on argument */
#define TOKENS_PER_LINE		5		/* num debug toks per line */

#define FILE_NOT_FOUND		1
#define FILE_FOUND		2
#define TOKEN_FOUND		3

/*
 * default flag information
 */
typedef struct {
  char		*de_string;			/* default name */
  long		de_flags;			/* default settings */
} default_t;

#define RUNTIME_FLAGS	(DEBUG_LOG_STATS | DEBUG_LOG_NONFREE | \
			 DEBUG_LOG_BAD_SPACE | DEBUG_LOG_UNKNOWN | \
			 DEBUG_CHECK_FENCE | \
			 DEBUG_CATCH_NULL)
#define LOW_FLAGS	(RUNTIME_FLAGS | \
			 DEBUG_LOG_ELAPSED_TIME | \
			 DEBUG_FREE_BLANK | DEBUG_ERROR_ABORT | \
			 DEBUG_ALLOC_BLANK)
#define MEDIUM_FLAGS	(LOW_FLAGS | \
			 DEBUG_CHECK_HEAP | DEBUG_CHECK_LISTS | \
			 DEBUG_REALLOC_COPY)
#define HIGH_FLAGS	(MEDIUM_FLAGS | \
			 DEBUG_CHECK_BLANK | DEBUG_CHECK_FUNCS)
#define ALL_FLAGS	(HIGH_FLAGS | \
			 DEBUG_LOG_TRANS | DEBUG_LOG_ADMIN | \
			 DEBUG_LOG_BLOCKS | \
			 DEBUG_HEAP_CHECK_MAP | DEBUG_NEVER_REUSE)
/* NOTE: print-error is not in this list because it is special */

static	default_t	defaults[] = {
  { "none",		0 },
  { "runtime",		RUNTIME_FLAGS },
  { "run",		RUNTIME_FLAGS },
  { "low",		LOW_FLAGS },
  { "med",		MEDIUM_FLAGS },
  { "medium",		MEDIUM_FLAGS },
  { "high",		HIGH_FLAGS },
  { "all",		ALL_FLAGS },
  { NULL }
};

/* argument variables */
static	char	*address = NULL;		/* for ADDRESS */
static	int	bourne_b = 0;			/* set bourne shell output */
static	int	cshell_b = 0;			/* set c-shell output */
static	int	clear_b = 0;			/* clear variables */
static	int	debug = 0;			/* for DEBUG */
static	int	errno_to_print = 0;		/* to print the error string */
static	int	gdb_b = 0;			/* set gdb output */
static	int	help_b = 0;			/* print help message */
static	char	*inpath = NULL;			/* for config-file path */
static	unsigned long interval = 0;		/* for setting INTERVAL */
static	int	thread_lock_on = 0;		/* for setting LOCK_ON */
static	int	keep_b = 0;			/* keep settings override -r */
static	int	list_tags_b = 0;		/* list rc tags */
static	int	debug_tokens_b = 0;		/* list debug tokens */
static	char	*logpath = NULL;		/* for LOGFILE setting */
static	int	long_tokens_b = 0;		/* long-tok output */
static	argv_array_t	minus;			/* tokens to remove */
static	int	make_changes_b = 1;		/* make no changes to env */
static	argv_array_t	plus;			/* tokens to add */
static	int	remove_auto_b = 0;		/* auto-remove settings */
static	int	short_tokens_b = 0;		/* short-tok output */
static	char	*start = NULL;			/* for START settings */
static	int	verbose_b = 0;			/* verbose flag */
static	int	very_verbose_b = 0;		/* very-verbose flag */
static	char	*tag = NULL;			/* maybe a tag argument */

static	argv_t	args[] = {
  { 'b',	"bourne",	ARGV_BOOL_INT,	&bourne_b,
    NULL,			"set output for bourne shells" },
  { ARGV_OR },
  { 'C',	"c-shell",	ARGV_BOOL_INT,	&cshell_b,
    NULL,			"set output for C-type shells" },
  { ARGV_OR },
  { 'g',	"gdb",		ARGV_BOOL_INT,	&gdb_b,
    NULL,			"set output for gdb parsing" },
  
  { 'L',	"long-tokens",	ARGV_BOOL_INT,	&long_tokens_b,
    NULL,			"output long-tokens not 0x..." },
  { ARGV_OR },
  { 'S',	"short-tokens",	ARGV_BOOL_INT,	&short_tokens_b,
    NULL,			"output short-tokens not 0x..." },
  
  { 'a',	"address",	ARGV_CHAR_P,	&address,
    "address:#",		"stop when malloc sees address" },
  { 'c',	"clear",	ARGV_BOOL_INT,	&clear_b,
    NULL,			"clear all variables not set" },
  { DEBUG_ARG,	"debug-mask",	ARGV_HEX,	&debug,
    "value",			"hex flag to set debug mask" },
  { 'D',	"debug-tokens",	ARGV_BOOL_INT,	&debug_tokens_b,
    NULL,			"list debug tokens" },
  { 'e',	"errno",	ARGV_INT,	&errno_to_print,
    "errno",			"print error string for errno" },
  { 'f',	"file",		ARGV_CHAR_P,	&inpath,
    "path",			"config if not ~/.mallocrc" },
  { 'h',	"help",		ARGV_BOOL_INT,	&help_b,
    NULL,			"print help message" },
  { INTERVAL_ARG, "interval",	ARGV_U_LONG,	&interval,
    "value",			"check heap every number times" },
  { 'k',	"keep",		ARGV_BOOL_INT,	&keep_b,
    NULL,			"keep settings (override -r)" },
  { 'l',	"logfile",	ARGV_CHAR_P,	&logpath,
    "path",			"file to log messages to" },
  { 'm',	"minus",	ARGV_CHAR_P | ARGV_FLAG_ARRAY,	&minus,
    "token(s)",			"del tokens from current debug" },
  { 'n',	"no-changes",	ARGV_BOOL_NEG,	&make_changes_b,
    NULL,			"make no changes to the env" },
  { THREAD_LOCK_ON_ARG, "lock-on", ARGV_INT,	&thread_lock_on,
    "number",			"number of times to not lock" },
  { 'p',	"plus",		ARGV_CHAR_P | ARGV_FLAG_ARRAY,	&plus,
    "token(s)",			"add tokens to current debug" },
  { 'r',	"remove",	ARGV_BOOL_INT,	&remove_auto_b,
    NULL,			"remove other settings if tag" },
  { 's',	"start",	ARGV_CHAR_P,	&start,
    "file:line",		"start check heap after this" },
  { 't',	"list-tags",	ARGV_BOOL_INT,	&list_tags_b,
    NULL,			"list tags in rc file" },
  { 'v',	"verbose",	ARGV_BOOL_INT,	&verbose_b,
    NULL,			"turn on verbose output" },
  { 'V',	"very-verbose",	ARGV_BOOL_INT,	&very_verbose_b,
    NULL,			"turn on very-verbose output" },
  { ARGV_MAYBE,	NULL,		ARGV_CHAR_P,	&tag,
    "tag",			"debug token to find in rc" },
  { ARGV_LAST }
};

/*
 * list of bourne shells
 */
static	char	*sh_shells[] = { "sh", "ash", "bash", "ksh", "zsh", NULL };

/*
 * try a check out the shell env variable to see what form of shell
 * commands we should output
 */
static	void	choose_shell(void)
{
  const char	*shell, *shell_p;
  int		shell_c;
  
  shell = getenv(SHELL_ENVIRON);
  if (shell == NULL) {
    /* oh well, we just guess on c-shell */
    cshell_b = 1;
    return;
  }
  
  shell_p = strrchr(shell, '/');
  if (shell_p == NULL) {
    shell_p = shell;
  }
  else {
    shell_p++;
  }
  
  for (shell_c = 0; sh_shells[shell_c] != NULL; shell_c++) {
    if (strcmp(sh_shells[shell_c], shell_p) == 0) {
      bourne_b = 1;
      return;
    }
  }
  
  cshell_b = 1;
}

/*
 * dump the current flags set in the debug variable VAL
 */
static	void	dump_debug(const int val)
{
  attr_t	*attr_p;
  int		tok_c = 0, work = val;
  
  for (attr_p = attributes; attr_p->at_string != NULL; attr_p++) {
    /* the below is necessary to handle the 'none' HACK */
    if ((work == 0 && attr_p->at_value == 0)
	|| (attr_p->at_value != 0
	    && BIT_IS_SET(work, attr_p->at_value))) {
      BIT_CLEAR(work, attr_p->at_value);
      
      if (tok_c == 0) {
	(void)fprintf(stderr, "   ");
      }
      
      if (very_verbose_b) {
	(void)fprintf(stderr, "%s -- %s", attr_p->at_string, attr_p->at_desc);
      }
      else {
	(void)fprintf(stderr, "%s", attr_p->at_string);
	if (work != 0) {
	  (void)fprintf(stderr, ", ");
	}
	tok_c = (tok_c + 1) % TOKENS_PER_LINE;
      }
      
      if (tok_c == 0) {
	(void)fprintf(stderr, "\n");
      }
      
      if (work == 0) {
	break;
      }
    }
  }
  
  if (tok_c != 0) {
    (void)fprintf(stderr, "\n");
  }
  
  if (work != 0) {
    (void)fprintf(stderr, "%s: warning, unknown debug flags: %#x\n",
		  argv_program, work);
  }
}

/*
 * translate TOK into its proper value which is returned
 */
static	long	token_to_value(const char *tok)
{
  attr_t	*attr_p;
  
  /* find the matching attribute string */
  for (attr_p = attributes; attr_p->at_string != NULL; attr_p++) {
    if (strcmp(tok, attr_p->at_string) == 0
	|| strcmp(tok, attr_p->at_short) == 0) {
      break;
    }
  }
  
  if (attr_p->at_string == NULL) {
    (void)fprintf(stderr, "%s: unknown token '%s'\n", argv_program, tok);
    return 0;
  }
  
  /* if we have a 0 value and not none then this is a disabled token */
  if (attr_p->at_value == 0 && strcmp(tok, "none") != 0) {
    (void)fprintf(stderr, "%s: token '%s' has been disabled: %s\n",
		  argv_program, tok, attr_p->at_desc);
    return 0;
  }
  
  return attr_p->at_value;
}

/*
 * Read in the next token from INFILE.  It passes back the returned
 * debug value in DEBUG_P.  Passes back the matching TOKEN of
 * TOKEN_SIZE.  Returns 1 if there was a next else 0.
 */
static	int	read_next_token(FILE *infile, long *debug_p,
				char *token, const int token_size)
{
  int	cont_b = 0, found_b = 0;
  long	new_debug = 0;
  char	buf[1024], *tok_p, *buf_p;
  
  while (fgets(buf, sizeof(buf), infile) != NULL) {
    
    /* ignore comments and empty lines */
    if (buf[0] == '#' || buf[0] == '\n') {
      continue;
    }
    
    /* chop off the ending \n */
    buf_p = strrchr(buf, '\n');
    SET_POINTER(buf_p, '\0');
    
    buf_p = buf;
    
    /* if we're not continuing then we need to process a tag */
    if (! cont_b) {
      
      /* get the first token on the line */
      tok_p = strsep(&buf_p, TOKENIZE_EQUALS);
      if (tok_p == NULL) {
	continue;
      }
      if (*tok_p == '\0') {
	(void)fprintf(stderr, "Invalid start of line: %s\n", buf_p);
	continue;
      }
      
      /* save the token */
      if (token != NULL) {
	(void)strncpy(token, tok_p, token_size);
	token[token_size - 1] = '\0';
      }
      found_b = 1;
    }
    
    cont_b = 0;
    
    while (1) {
      /* get the next token */
      tok_p = strsep(&buf_p, TOKENIZE_CHARS);
      if (tok_p == NULL) {
	break;
      }
      if (*tok_p == '\0') {
	continue;
      }
      
      /* do we have a continuation character? */
      if (strcmp(tok_p, "\\") == 0) {
	cont_b = 1;
	break;
      }
      
      new_debug |= token_to_value(tok_p);
    }
    
    /* are we done? */
    if (! cont_b) {
      break;
    }
  }
  
  SET_POINTER(debug_p, new_debug);
  
  if (found_b) {
    return 1;
  }
  else {
    return 0;
  }
}

/*
 * Read in a rc file from PATH and process it looking for the
 * specified DEBUG_VALUE or TAG_FIND token.  It passes back the
 * returned debug value in DEBUG_P.  Passes back the matching TOKEN of
 * TOKEN_SIZE.
 *
 * Returns FILE_NOT_FOUND, FILE_FOUND, or TOKEN_FOUND.
 */
static	int	read_rc_file(const char *path, const long debug_value,
			     const char *tag_find, long *debug_p,
			     char *token, const int token_size)
{
  FILE	*infile;
  int	found_b = 0;
  char	next_token[64];
  long	new_debug;
  
  /* open the path */
  infile = fopen(path, "r");
  if (infile == NULL) {
    return FILE_NOT_FOUND;
  }
  
  /* run through the tokens, looking for a match */
  while (read_next_token(infile, &new_debug, next_token,
			 sizeof(next_token)) == 1) {
    
    /* are we looking for a tag? */
    if (tag_find != NULL && strcmp(tag_find, next_token) == 0) {
      found_b = 1;
      break;
    }
    
    /* are we looking for a debug-value? */
    if (debug_value > 0 && debug_value == new_debug) {
      found_b = 1;
      break;
    }
  }
  
  (void)fclose(infile);
  
  SET_POINTER(debug_p, new_debug);
  if (token != NULL) {
    strncpy(token, next_token, token_size);
    token[token_size - 1] = '\0';
  }
  
  if (found_b) {
    return TOKEN_FOUND;
  }
  else {
    return FILE_FOUND;
  }
}

/*
 * Process the user configuration looking for the TAG_FIND.  If it is
 * null then look for DEBUG_VALUE in the file and copy the token found
 * into TOKEN of TOKEN_SIZE.  Routine returns the new debug value
 * matching tag.
 */
static	long	process(const long debug_value, const char *tag_find,
			char *token, const int token_size)
{
  char		path[1024], *path_p;
  default_t	*def_p;
  const char	*home_p;
  int		ret;
  long		new_debug = 0;
  
  /* do we need to have a home variable? */
  if (inpath == NULL) {
    
    /* first we try to read the RC file from the current directory */
    ret = read_rc_file(DEFAULT_CONFIG, debug_value, tag_find, &new_debug,
		       token, token_size);
    /* did we find the correct value in the file? */
    if (ret == TOKEN_FOUND) {
      return new_debug;
    }
    
    /* if we did not find the file, check the home directory */
    if (ret == FILE_FOUND) {
      path_p = DEFAULT_CONFIG;
    }
    else {
      /* find our home directory */
      home_p = getenv(HOME_ENVIRON);
      if (home_p == NULL) {
	(void)fprintf(stderr, "%s: could not find variable '%s'\n",
		      argv_program, HOME_ENVIRON);
	exit(1);
      }
      
      (void)loc_snprintf(path, sizeof(path), "%s/%s", home_p, DEFAULT_CONFIG);
      
      /* read in the file from our home directory */
      ret = read_rc_file(path, debug_value, tag_find, &new_debug,
			 token, token_size);
      /* did we find the correct value in the file? */
      if (ret == TOKEN_FOUND) {
	return new_debug;
      }
      if (ret == FILE_FOUND) {
	path_p = path;
      }
      else {
	path_p = NULL;
      }
    }
  }
  else {
    /* read in the specified file */
    ret = read_rc_file(inpath, debug_value, tag_find, &new_debug,
		       token, token_size);
    /* did we find the correct value in the file? */
    if (ret == TOKEN_FOUND) {
      return new_debug;
    }
    /* if the specified was not found, return error */
    if (ret != FILE_FOUND) {
      (void)fprintf(stderr, "%s: could not read '%s': ",
		    argv_program, inpath);
      perror("");
      exit(1);
    }
    path_p = inpath;
  }
  
  /* if tag-find is NULL we assume we are looking for a debug-value */
  if (tag_find == NULL) {
    
    /* now look for the value in the default token list */
    if (token != NULL) {
      for (def_p = defaults; def_p->de_string != NULL; def_p++) {
	if (def_p->de_flags == debug_value) {
	  strncpy(token, def_p->de_string, token_size);
	  token[token_size - 1] = '\0';
	  new_debug = def_p->de_flags;
	  break;
	}
      }
      if (def_p->de_string == NULL) {
	strncpy(token, "unknown", token_size);
	token[token_size - 1] = '\0';
	new_debug = 0;
      }
    }
  }
  else {
    
    /* now look for the token in the default token list */
    for (def_p = defaults; def_p->de_string != NULL; def_p++) {
      if (strcmp(tag_find, def_p->de_string) == 0) {
	new_debug = def_p->de_flags;
	break;
      }
    }
    
    /* did we not find the token? */
    if (def_p->de_string == NULL) {
      if (path_p == NULL) {
	(void)fprintf(stderr, "%s: unknown tag '%s'\n",
		      argv_program, tag_find);
      }
      else {
	(void)fprintf(stderr, "%s: could not find tag '%s' in '%s'\n",
		      argv_program, tag_find, path_p);
      }
      exit(1);
    }
  }
  
  return new_debug;
}

/*
 * List the tags that in the files.
 */
static	void	list_tags(void)
{
  char		path[1024], *path_p, token[64];
  default_t	*def_p;
  const char	*home_p;
  long		new_debug = 0;
  FILE		*rc_file;
  
  /* do we need to have a home variable? */
  if (inpath == NULL) {
    
    /* first we try to read the RC file from the current directory */
    rc_file = fopen(DEFAULT_CONFIG, "r");
    if (rc_file == NULL) {
      
      /* if no file in current directory, try home directory */
      home_p = getenv(HOME_ENVIRON);
      if (home_p == NULL) {
	(void)fprintf(stderr, "%s: could not find variable '%s'\n",
		      argv_program, HOME_ENVIRON);
	exit(1);
      }
      
      (void)loc_snprintf(path, sizeof(path), "%s/%s", home_p, DEFAULT_CONFIG);
      path_p = path;
      
      rc_file = fopen(path, "r");
      /* we don't check for error right here */
    }
    else {
      path_p = DEFAULT_CONFIG;
    }
  }
  else {
    
    /* open the specified file */
    rc_file = fopen(inpath, "r");
    /* we assume that if the file was specified, it must be there */
    if (rc_file == NULL) {
      (void)fprintf(stderr, "%s: could not read '%s': ",
		    argv_program, inpath);
      perror("");
      exit(1);
    }
    path_p = inpath;
  }
  
  if (rc_file != NULL) {
    (void)fprintf(stderr, "Tags available from '%s':\n", path_p);
    
    while (read_next_token(rc_file, &new_debug, token, sizeof(token)) == 1) {
      if (verbose_b) {
	(void)fprintf(stderr, "%s (%#lx):\n", token, new_debug);
	dump_debug(new_debug);
      }
      else {
	(void)fprintf(stderr, "%s\n", token);
      }
    }
    
    (void)fclose(rc_file);
  }
  
  (void)fprintf(stderr, "\n");
  (void)fprintf(stderr, "Tags available by default:\n");
  
  for (def_p = defaults; def_p->de_string != NULL; def_p++) {
    if (verbose_b) {
      (void)fprintf(stderr, "%s (%#lx):\n",
		    def_p->de_string, def_p->de_flags);
      dump_debug(def_p->de_flags);
    }
    else {
      (void)fprintf(stderr, "%s\n", def_p->de_string);
    }
  }
}

/*
 * dump the current settings of the malloc variables
 */
static	void	dump_current(void)
{
  char		*lpath, *start_file, token[64];
  DMALLOC_PNT	addr;
  unsigned long	inter;
  long		addr_count;
  int		lock_on, start_line, start_count;
  unsigned int	flags;
  
  (void)fprintf(stderr, "Debug Malloc Utility: http://dmalloc.com/\n");
  (void)fprintf(stderr,
		"  For a list of the command-line options enter: %s --usage\n",
		argv_argv[0]);
  
  _dmalloc_environ_get(OPTIONS_ENVIRON, &addr, &addr_count, &flags,
		       &inter, &lock_on, &lpath,
		       &start_file, &start_line, &start_count);
  
  if (flags == 0) {
    (void)fprintf(stderr, "Debug-Flags  not-set\n");
  }
  else {
    (void)process(flags, NULL, token, sizeof(token));
    (void)fprintf(stderr, "Debug-Flags %#x (%u) (%s)\n",
		  flags, flags, token);
    if (verbose_b) {
      dump_debug(flags);
    }
  }
  
  if (addr == NULL) {
    (void)fprintf(stderr, "Address      not-set\n");
  }
  else {
    if (addr_count == 0) {
      (void)fprintf(stderr, "Address      %#lx\n", (long)addr);
    }
    else {
      (void)fprintf(stderr, "Address      %#lx, count = %ld\n",
		    (long)addr, addr_count);
    }
  }
  
  if (inter == 0) {
    (void)fprintf(stderr, "Interval     not-set\n");
  }
  else {
    (void)fprintf(stderr, "Interval     %lu\n", inter);
  }
  
  if (lock_on == 0) {
    (void)fprintf(stderr, "Lock-On      not-set\n");
  }
  else {
    (void)fprintf(stderr, "Lock-On      %d\n", lock_on);
  }
  
  if (lpath == NULL) {
    (void)fprintf(stderr, "Logpath      not-set\n");
  }
  else {
    (void)fprintf(stderr, "Logpath      '%s'\n", lpath);
  }
  
  if (start_file == NULL && start_count == 0) {
    (void)fprintf(stderr, "Start-File   not-set\n");
  }
  else if (start_count > 0) {
    (void)fprintf(stderr, "Start-Count  %d\n", start_count);
  }
  else {
    (void)fprintf(stderr, "Start-File   '%s', line = %d\n",
		  start_file, start_line);
  }
}

/*
 * output the code to set env VAR to VALUE
 */
static	void    set_variable(const char *var, const char *value)
{
  char	comm[1024];
  
  if (bourne_b) {
    (void)loc_snprintf(comm, sizeof(comm), "%s=%s\nexport %s\n",
		       var, value, var);
  }
  else if (gdb_b) {
    (void)loc_snprintf(comm, sizeof(comm), "set env %s %s\n", var, value);
  }
  else {
    (void)loc_snprintf(comm, sizeof(comm), "setenv %s %s\n", var, value);
  }
  
  if (make_changes_b) {
    (void)printf("%s", comm);
  }
  if ((! make_changes_b) || verbose_b) {
    (void)fprintf(stderr, "Outputed:\n");
    (void)fprintf(stderr, "%s", comm);
  }
}

/*
 * Returns the string for ERROR_NUM.
 */
static	char	*local_strerror(const int error_num)
{
  error_str_t	*err_p;
  
  for (err_p = error_list; err_p->es_error != 0; err_p++) {
    if (err_p->es_error == error_num) {
      return err_p->es_string;
    }
  }
  
  return INVALID_ERROR;
}

int	main(int argc, char **argv)
{
  char		buf[1024];
  int		set_b = 0;
  char		*lpath, *sfile;
  DMALLOC_PNT	addr;
  unsigned long	inter;
  long		addr_count;
  int		lock_on;
  int		sline, scount;
  unsigned int	flags;
  
  argv_help_string = "Sets dmalloc library env variables.  Also try --usage.";
  argv_version_string = dmalloc_version;
  
  argv_process(args, argc, argv);
  
  if (help_b) {
    (void)fprintf(stderr, "Debug Malloc Utility: http://dmalloc.com/\n");
    (void)fprintf(stderr,
		  "  This utility helps set the Debug Malloc environment variables.\n");
    (void)fprintf(stderr,
		  "  For a list of the command-line options enter: %s --usage\n",
		  argv_argv[0]);
    exit(0);
  }
  
  if (very_verbose_b) {
    verbose_b = 1;
  }
  
  /* try to figure out the shell we are using */
  if ((! bourne_b) && (! cshell_b) && (! gdb_b)) {
    choose_shell();
  }
  
  /* get the current debug information from the env variable */
  _dmalloc_environ_get(OPTIONS_ENVIRON, &addr, &addr_count, &flags, &inter,
		       &lock_on, &lpath, &sfile, &sline, &scount);
  
  /*
   * So, if a tag was specified on the command line then we set the
   * debug from it.  If it was not then we see if the debug flags were
   * set as a hex value from the -d.  If this was not used then take
   * the current value.
   */
  if (tag == NULL) {
    if (argv_was_used(args, DEBUG_ARG)) {
      set_b = 1;
      /* should we clear the rest? */
      if (remove_auto_b && (! keep_b)) {
	clear_b = 1;
      }
    }
    else {
      debug = flags;
    }
  }
  else {
    if (argv_was_used(args, DEBUG_ARG)) {
      (void)fprintf(stderr, "%s: warning -d ignored, processing tag '%s'\n",
		    argv_program, tag);
    }
    set_b = 1;
    debug = process(0L, tag, NULL, 0);
    /* should we clear the rest? */
    if (remove_auto_b && (! keep_b)) {
      clear_b = 1;
    }
  }
  
  if (plus.aa_entry_n > 0) {
    int		plus_c;
    for (plus_c = 0; plus_c < plus.aa_entry_n; plus_c++) {
      debug |= token_to_value(ARGV_ARRAY_ENTRY(plus, char *, plus_c));
      set_b = 1;
    }
  }
  
  if (minus.aa_entry_n > 0) {
    int		minus_c;
    for (minus_c = 0; minus_c < minus.aa_entry_n; minus_c++) {
      debug &= ~token_to_value(ARGV_ARRAY_ENTRY(minus, char *, minus_c));
      set_b = 1;
    }
  }
  
  if (address != NULL) {
    _dmalloc_address_break(address, &addr, &addr_count);
    set_b = 1;
  }
  else if (clear_b) {
    addr = NULL;
  }
  
  if (argv_was_used(args, INTERVAL_ARG)) {
    inter = interval;
    set_b = 1;
  }
  else if (clear_b) {
    inter = 0;
  }
  
  /*
   * NOTE: this should be after the debug setting which this tests.
   */
  if (argv_was_used(args, THREAD_LOCK_ON_ARG)) {
    lock_on = thread_lock_on;
    set_b = 1;
    if (BIT_IS_SET(debug, DEBUG_FORCE_LINEAR)) {
      (void)fprintf(stderr,
		    "WARNING: the force-linear flag is enabled\n");
    }
  }
  else if (clear_b) {
    lock_on = 0;
  }
  
  if (logpath != NULL) {
    lpath = logpath;
    set_b = 1;
  }
  else if (clear_b) {
    lpath = NULL;
  }
  
  if (start != NULL) {
    _dmalloc_start_break(start, &sfile, &sline, &scount);
    set_b = 1;
  }
  else if (clear_b) {
    sfile = NULL;
    sline = 0;
    scount = 0;
  }
  
  if (errno_to_print > 0) {
    (void)fprintf(stderr, "%s: dmalloc_errno value '%d' = \n",
		  argv_program, errno_to_print);
    (void)fprintf(stderr, "   '%s'\n", local_strerror(errno_to_print));
  }
  
  if (list_tags_b) {
    list_tags();
  }
  
  if (debug_tokens_b) {
    attr_t		*attr_p;
    unsigned int	left = 0x7fffffff;
    
    (void)fprintf(stderr, "Debug Tokens:\n");
    for (attr_p = attributes; attr_p->at_string != NULL; attr_p++) {
      /* skip any disabled tokens */
      if (attr_p->at_value == 0 && strcmp(attr_p->at_string, "none") != 0) {
	continue;
      }
      if (attr_p->at_value != 0 && (! BIT_IS_SET(left, attr_p->at_value))) {
	/* skip any tokens we've seen before */
	continue;
      }
      if (very_verbose_b) {
	(void)fprintf(stderr, "%s (%s) -- %s (%#lx)\n",
		      attr_p->at_string, attr_p->at_short, attr_p->at_desc,
		      attr_p->at_value);
      }
      else if (verbose_b) {
	(void)fprintf(stderr, "%s -- %s\n",
		      attr_p->at_string, attr_p->at_desc);
      }
      else {
	(void)fprintf(stderr, "%s\n", attr_p->at_string);
      }
      BIT_CLEAR(left, attr_p->at_value);
    }
  }
  
  if (clear_b || set_b) {
    _dmalloc_environ_set(buf, sizeof(buf), long_tokens_b, short_tokens_b,
			 addr, addr_count, debug, inter, lock_on, lpath,
			 sfile, sline, scount);
    set_variable(OPTIONS_ENVIRON, buf);
  }
  else if (errno_to_print == 0
	   && (! list_tags_b)
	   && (! debug_tokens_b)) {
    dump_current();
  }
  
  argv_cleanup(args);
  
  exit(0);
}
