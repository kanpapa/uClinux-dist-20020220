
#include	<sys/param.h>
#include	<sys/types.h>
#include	<sys/time.h>
#include	<stdio.h>
#include	<netdb.h>
#include	<unistd.h>
#include 	<sys/file.h>

#include	"ctypes.h"
#include	"local.h"
#include	"debug.h"
#include	"miv.h"
#include	"asn.h"
#include	"mix.h"
#include	"systm.h"
//#include	"kmem.h"

#define			systmStringSize		(2 * MAXHOSTNAMELEN)

#ifdef NeTtel
#define PRIVATENUM	6492
#else
#define PRIVATENUM	6491
#endif

static	CCharType	systmDescrText[systmStringSize];		//*****Change to HOSTANME + version
static	CCharType	systmHostName[(MAXHOSTNAMELEN + 1)];
static	MivStrType	systmDescrStr;
static	CCharType	systmContText[systmStringSize];
static	MivStrType	systmContStr;
static	CCharType	systmNameText[systmStringSize];
static	MivStrType	systmNameStr;
static	CCharType	systmLocText[systmStringSize];
static	MivStrType	systmLocStr;

static	CIntsType	systmServInt;

static	CByteType	systmObjId [ systmStringSize ];
static	MivStrType	systmIdStr;

static	struct	timeval	systmBootTime;

static	MixStatusType	systmTimeRelease (mix)

MixCookieType		mix;

{
	mix = mix;
	return (smpErrorGeneric);
}


static	MixStatusType	systmTimeNoSet (mix, name, namelen, value)

MixCookieType		mix;
MixNamePtrType		name;
MixLengthType		namelen;
AsnIdType		value;

{
	mix = mix;
	name = name;
	namelen = namelen;
	value = value;
	return (smpErrorReadOnly);
}

static	MixStatusType	systmTimeCreate (mix, name, namelen, value)

MixCookieType		mix;
MixNamePtrType		name;
MixLengthType		namelen;
AsnIdType		value;

{
	mix = mix;
	name = name;
	namelen = namelen;
	value = value;
	return (smpErrorGeneric);
}

static	MixStatusType	systmTimeDestroy (mix, name, namelen)

MixCookieType		mix;
MixNamePtrType		name;
MixLengthType		namelen;

{
	mix = mix;
	name = name;
	namelen = namelen;
	return (smpErrorGeneric);
}

static	AsnIdType	systmTimeGet (mix, name, namelen)

MixCookieType		mix;
MixNamePtrType		name;
MixLengthType		namelen;

{
	struct	timeval		now;
	CUnslType		uptime;

	mix = mix;
	if ((namelen != (MixLengthType) 1) ||
		(*name != (MixNameType) 0)) {
		return ((AsnIdType) 0);
	}
	else {
		(void) gettimeofday (& now, (struct timezone *) 0);
		uptime = (CUnslType) (now.tv_sec - systmBootTime.tv_sec) *
			(CUnslType) 100;
		return (asnUnsl (asnClassApplication, (AsnTagType) 3, uptime));
	}
}

static	AsnIdType	systmTimeNext (mix, name, namelenp)

MixCookieType		mix;
MixNamePtrType		name;
MixLengthPtrType	namelenp;

{
	struct	timeval		now;
	CUnslType		uptime;

	mix = mix;
	if (*namelenp != (MixLengthType) 0) {
		return ((AsnIdType) 0);
	}
	else {
		*namelenp = (MixLengthType) 1;
		*name = (MixNameType) 0;
		DEBUG2 ("systmTimeNext: boot %d %d\n",
			systmBootTime.tv_sec,
			systmBootTime.tv_usec);
		(void) gettimeofday (& now, (struct timezone *) 0);
		DEBUG2 ("systmTimeNext: now %d %d\n",
			now.tv_sec,
			now.tv_usec);
		uptime = (CUnslType) (now.tv_sec - systmBootTime.tv_sec) *
			(CUnslType) 100;
		DEBUG1 ("systmTimeNext: uptime %d\n", uptime);
		return (asnUnsl (asnClassApplication, (AsnTagType) 3, uptime));
	}
}

static	MixOpsType	systmTimeOps	= {

			systmTimeRelease,
			systmTimeCreate,
			systmTimeDestroy,
			systmTimeNext,
			systmTimeGet,
			systmTimeNoSet

			};

CVoidType		systmInit ()

{
	long		gethostid();
	int		gethostname();
	long		hostid;
	unsigned char *ep;
	static int nr = 0;
	char version_descr[256] = "Linux";
	FILE *in;
 	char tmp [256];
	CCharType	playArea[systmStringSize];
	CIntfType	k;
	 
 if ((in = fopen ("/etc/version", "r")))
    {
	if (fgets (tmp, 256, in) > 0)
	  { 
	      tmp [strlen (tmp) - 1] = 0;
	      strcpy (version_descr, tmp);
	  }
	fclose (in);
    }
  else
    {
	strcpy (version_descr, "Unknown");
	printf ("snmpd: cannot open /etc/version.\n");
    }
	(void)sprintf(systmDescrText, "%s",version_descr);	
	systmDescrStr.mivStrData = (CBytePtrType) systmDescrText;
	systmDescrStr.mivStrMaxLen = (CUnsfType) systmStringSize;
	systmDescrStr.mivStrLen = (CUnsfType) strlen (systmDescrText);

	(void) mivStringRO ((MixNamePtrType) "\53\6\1\2\1\1\1",
		(MixLengthType) 7, & systmDescrStr);


	ep = (unsigned char *) (0xf0006000);
	if ((ep[0] == 0xff) && (ep[1] == 0xff) && (ep[2] == 0xff) &&
	    (ep[3] == 0xff) && (ep[4] == 0xff) && (ep[5] == 0xff))
		hostid = 0x00;
	else
		//hostid = (ep[2]<<24)+(ep[3]<<16)+(ep[4]<<8)+ep[5];
		hostid = (ep[4]<<8)+ep[5];

	DEBUG1 ("systmInit: Hostid %d\n", hostid);
	(void) sprintf (playArea, "1.3.6.1.4.1.%u.%u", PRIVATENUM, hostid);
	k = oidEncode (systmObjId, (CIntfType) systmStringSize, playArea);
	if (k > (CIntfType) 0) {
		systmIdStr.mivStrData = systmObjId;
		systmIdStr.mivStrMaxLen = (CUnsfType) systmStringSize;
		systmIdStr.mivStrLen = (CUnsfType) k;

		(void) mivObjectIdRO ((MixNamePtrType) "\53\6\1\2\1\1\2",
			(MixLengthType) 7, & systmIdStr);
	}
	
	(void) gettimeofday (&systmBootTime, (struct timezone *) 0);	
	(void) misExport ((MixNamePtrType) "\53\6\1\2\1\1\3",
		(MixLengthType) 7, & systmTimeOps, (MixCookieType) 0);

	/**Contact**/
	systmContText[MAXHOSTNAMELEN]=(CCharType)0;
	(void)sprintf(systmContText, "Tom Dolsky");
	systmContStr.mivStrData = (CBytePtrType) systmContText;
	systmContStr.mivStrMaxLen = (CUnsfType) systmStringSize;
	systmContStr.mivStrLen = (CUnsfType) strlen (systmContText);
	(void) mivStringRW ((MixNamePtrType) "\53\6\1\2\1\1\4",
		(MixLengthType) 7, & systmContStr);
	/**End Contact**/

	/**Name**/
	if (gethostname((char *)systmHostName,(int)MAXHOSTNAMELEN) < 0) 
		{
		(void)sprintf(systmDescrText,"Unknown Hostname");
		}
	else 
		{
		systmHostName[MAXHOSTNAMELEN]=(CCharType)0;
		(void)sprintf(systmNameText, "%s",systmHostName);
		}
	systmNameStr.mivStrData = (CBytePtrType) systmNameText;
	systmNameStr.mivStrMaxLen = (CUnsfType) systmStringSize;
	systmNameStr.mivStrLen = (CUnsfType) strlen (systmNameText);
	(void) mivStringRW ((MixNamePtrType) "\53\6\1\2\1\1\5",
		(MixLengthType) 7, & systmNameStr);
	/**End Name**/

	/**Location**/
	systmLocText[MAXHOSTNAMELEN]=(CCharType)0;
	(void)sprintf(systmLocText, "Tom's Office");
	systmLocStr.mivStrData = (CBytePtrType) systmLocText;
	systmLocStr.mivStrMaxLen = (CUnsfType) systmStringSize;
	systmLocStr.mivStrLen = (CUnsfType) strlen (systmLocText);
	(void) mivStringRW ((MixNamePtrType) "\53\6\1\2\1\1\6",
		(MixLengthType) 7, & systmLocStr);
	/**End Location**/

	/**Services**/
	systmServInt=(CIntsType)6;
	(void) mivIntlRO ((MixNamePtrType) "\53\6\1\2\1\1\7",
		(MixLengthType) 7, & systmServInt);
	/**End Services**/

}

