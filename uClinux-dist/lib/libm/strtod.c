#include <stdio.h>
#include <ctype.h>
#include <string.h>

#include "mconf.h"

#include <stdio.h>

/* fp scan actions */
#define F_NADA	0	/* just change state */
#define F_SIGN	1	/* set sign */
#define F_ESIGN	2	/* set exponent's sign */
#define F_INT	3	/* adjust integer part */
#define F_FRAC	4	/* adjust fraction part */
#define F_EXP	5	/* adjust exponent part */
#define F_QUIT	6

#define NSTATE	8
#define FS_INIT		0	/* initial state */
#define FS_SIGNED	1	/* saw sign */
#define FS_DIGS		2	/* saw digits, no . */
#define FS_DOT		3	/* saw ., no digits */
#define FS_DD		4	/* saw digits and . */
#define FS_E		5	/* saw 'e' */
#define FS_ESIGN	6	/* saw exp's sign */
#define FS_EDIGS	7	/* saw exp's digits */

#define FC_DIG		0
#define FC_DOT		1
#define FC_E		2
#define FC_SIGN		3

/* given transition,state do what action? */
static unsigned char fp_do[][NSTATE] = {
	{F_INT,F_INT,F_INT,
	 F_FRAC,F_FRAC,
	 F_EXP,F_EXP,F_EXP},	/* see digit */
	{F_NADA,F_NADA,F_NADA,
	 F_QUIT,F_QUIT,F_QUIT,F_QUIT,F_QUIT},	/* see '.' */
	{F_QUIT,F_QUIT,
	 F_NADA,F_QUIT,F_NADA,
	 F_QUIT,F_QUIT,F_QUIT},	/* see e/E */
	{F_SIGN,F_QUIT,F_QUIT,F_QUIT,F_QUIT,
	 F_ESIGN,F_QUIT,F_QUIT},	/* see sign */
};
/* given transition,state what is new state? */
static unsigned char fp_ns[][NSTATE] = {
	{FS_DIGS,FS_DIGS,FS_DIGS,
	 FS_DD,FS_DD,
	 FS_EDIGS,FS_EDIGS,FS_EDIGS},	/* see digit */
	{FS_DOT,FS_DOT,FS_DD,
	 },	/* see '.' */
	{0,0,
	 FS_E,0,FS_E,
	},	/* see e/E */
	{FS_SIGNED,0,0,0,0,
	 FS_ESIGN,0,0},	/* see sign */
};
/* which states are valid terminators? */
static unsigned char fp_sval[NSTATE] = {
	0,0,1,0,1,0,0,1
};


#ifdef __STDC__
double strtod(const char * nptr, char **endptr)
#else
double strtod(nptr, endptr)
__const char *nptr;
char **endptr;
#endif
{
    const char * c = nptr;
    int fstate = FS_INIT;
    int neg = 0;
    int eneg = 0;
    int n = 0;
    int frac = 0;
    int expo = 0;
    int fraclen = 0;
    int width=-1;
    int trans=0;
    
    while (*c && width--)
    {
       if (*c >= '0' && *c <= '9')
	  trans = FC_DIG;
       else if (*c == '.')
	  trans = FC_DOT;
       else if (*c == '+' || *c == '-')
	  trans = FC_SIGN;
       else if (tolower(*c) == 'e')
	  trans = FC_E;
       else
	  goto fdone;

       switch (fp_do[trans][fstate])
       {
       case F_SIGN:
	  neg = (*c == '-');
	  break;
       case F_ESIGN:
	  eneg = (*c == '-');
	  break;
       case F_INT:
	  n = 10 * n + (*c - '0');
	  break;
       case F_FRAC:
	  frac = 10 * frac + (*c - '0');
	  fraclen++;
	  break;
       case F_EXP:
	  expo = 10 * expo + (*c - '0');
	  break;
       case F_QUIT:
	  goto fdone;
       }
       fstate = fp_ns[trans][fstate];
       c++;
    }

  fdone:
    if (!fp_sval[fstate]) {
       if (endptr)
          *endptr = (char *) nptr;
       return 0;
    }
    if (endptr)
       *endptr = (char *) c;
       
    return fp_scan(neg, eneg, n, frac, expo, fraclen);

}

