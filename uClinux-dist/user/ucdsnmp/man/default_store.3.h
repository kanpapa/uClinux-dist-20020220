/* These definitions correspond with the "storid" argument to the API */
#define DS_LIBRARY_ID     0
#define DS_APPLICATION_ID 1
#define DS_TOKEN_ID       2

/* These definitions correspond with the "which" argument to the API,
   when the storeid argument is DS_LIBRARY_ID */
/* library booleans */
#define DS_LIB_MIB_ERRORS          0
#define DS_LIB_SAVE_MIB_DESCRS     1
#define DS_LIB_MIB_COMMENT_TERM    2
#define DS_LIB_MIB_PARSE_LABEL     3
#define DS_LIB_DUMP_PACKET         4
#define DS_LIB_LOG_TIMESTAMP       5
#define DS_LIB_DONT_READ_CONFIGS   6
#define DS_LIB_MIB_REPLACE         7  /* replace objects from latest module */
#define DS_LIB_PRINT_NUMERIC_ENUM  8  /* print only numeric enum values */
#define DS_LIB_PRINT_NUMERIC_OIDS  9  /* print only numeric enum values */
#define DS_LIB_DONT_BREAKDOWN_OIDS 10 /* dont print oid indexes specially */
#define DS_LIB_ALARM_DONT_USE_SIG  11 /* don't use the alarm() signal */
#define DS_LIB_PRINT_FULL_OID      12 /* print fully qualified oids */
#define DS_LIB_QUICK_PRINT         13 /* print very brief output for parsing */
#define DS_LIB_RANDOM_ACCESS	   14 /* random access to oid labels */
#define DS_LIB_REGEX_ACCESS	   15 /* regex matching to oid labels */
#define DS_LIB_DONT_CHECK_RANGE    16 /* don't check values for ranges on send*/
#define DS_LIB_NO_TOKEN_WARNINGS   17 /* no warn about unknown config tokens */

/* library integers */
#define DS_LIB_MIB_WARNINGS  0
#define DS_LIB_SECLEVEL      1
#define DS_LIB_SNMPVERSION   2
#define DS_LIB_DEFAULT_PORT  3
#define DS_LIB_PRINT_SUFFIX_ONLY 4 /* print out only a single oid node  == 1.
                                      like #1 but supply mib module too == 2. */

/* library strings */
#define DS_LIB_SECNAME         0
#define DS_LIB_CONTEXT         1
#define DS_LIB_PASSPHRASE      2
#define DS_LIB_AUTHPASSPHRASE  3
#define DS_LIB_PRIVPASSPHRASE  4
#define DS_LIB_OPTIONALCONFIG  5
#define DS_LIB_APPTYPE         6
#define DS_LIB_COMMUNITY       7

