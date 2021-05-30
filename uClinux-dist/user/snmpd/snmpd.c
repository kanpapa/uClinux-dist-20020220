#include	<sys/types.h>
#include	<sys/socket.h>
#include	<netinet/in.h>
#include	<signal.h>

#include	<stdio.h>
#include	<netdb.h>
#include	<strings.h>

#include	"host.h"
#include	"ctypes.h"
#include	"debug.h"
#include	"rdx.h"
#include	"smp.h"
#include	"mis.h"
#include	"miv.h"
#include	"aps.h"
#include	"ap0.h"
#include	"asn.h"
#include	"asl.h"
#include	"avl.h"
#include	"udp.h"
#include	"systm.h"
//#include	"rte.h"
#include	"tcp_vars.h"
#include	"ip_vars.h"
#include	"iface_vars.h"
//#include	"at_vars.h"
#include	"icmp_vars.h"
#include	"udp_vars.h"

#define		cmdStringSize		(32)
#define		cmdBufferSize		(2048)

static void done(int sig)
{
  exit(0);
}

static	void	cmdInit ()

{
	aslInit ();
	asnInit ();
	misInit ();
	avlInit ();
	mixInit ();
	apsInit ();
	ap0Init ();
	smpInit ();

//	kmemInit ();
	systmInit ();
//	rteInit ();
	ipInit ();
//	apInit ();
	ifaceInit ();
	tcpInit ();
	icmpInit ();
	udpInit ();
}

static  CIntfType       usage (s)

CCharPtrType            s;

{
        fprintf (stderr, "Usage: %s", s);
        fprintf (stderr, " [-h lhost]");
        fprintf (stderr, " [-p lport]");
        fprintf (stderr, " [-c community]");
        fprintf (stderr, "\n");
        return (1);
}

static	SmpStatusType	myUpCall (smp, community, req)

SmpIdType		smp;
ApsIdType		community;
SmpRequestPtrType	req;

{
	smp = smp;
	community = community;
	req = req;
	printf ("Upcall:\n");
	return (errOk);
}

int			snmpdCommand (argc, argv)

int			argc;
char			**argv;

{
	int			s;
	int			salen;
	int			result;
	struct	sockaddr	salocal;
	struct	sockaddr	saremote;
	struct	sockaddr_in	*sin;
	struct	servent		*svp;

        u_long                  lhost;
        u_short                 lport;

	CByteType		buf [ cmdBufferSize ];
	CBytePtrType		bp;
	SmpIdType		smp;
	SmpSocketType		udp;
	ApsIdType		communityId;
        CCharPtrType            *ap;
        CCharPtrType            cp;
        CBoolType               noerror;
	CUnslType		number;

        CCharPtrType            communityString;
        CCharPtrType            lhostString;
        CCharPtrType            lportString;

	communityString = (CCharPtrType) 0;
	lhostString = (CCharPtrType) 0;
	lportString = (CCharPtrType) 0;

	ap = (CCharPtrType *) argv + 1;
	argc--;
	noerror = TRUE;
	while ((argc != 0) && (**ap == (CCharType) '-') && (noerror)) {
		cp = *ap;
		cp++;
		ap++;
		argc--;
		while ((*cp != (CCharType) 0) && (noerror)) {
			switch (*cp) {

			case 'c':
				argc--;
				communityString = *ap++;
				break;

			case 'h':
				argc--;
				lhostString = *ap++;
				break;

			case 'p':
				argc--;
				lportString = *ap++;
				break;

			default:
				noerror = FALSE;
				break;
			}
			cp++;
		}
	}

	if ((! noerror) || (argc > 0)) {
		return ((int) usage ((CCharPtrType) argv [ 0 ]));
	}

	if (lhostString != (CCharPtrType) 0) {
		lhost = (u_long) hostAddress (lhostString);
		if (lhost == (u_long) -1) {
			fprintf (stderr, "%s: Bad foreign host: %s\n",
				argv [ 0 ], lhostString);
			return (2);
		}
	}
	else {
		lhost = (u_long) 0;
	}

	if (lportString != (CCharPtrType) 0) {
                if (rdxDecodeAny (& number, lportString) < (CIntfType) 0) {
                        fprintf (stderr, "%s: Bad local port: %s\n",
                                argv [ 0 ], lportString);
                        return (2);
                }
                else {
                        lport = htons ((u_short) number);
                }
        }
        else 
		{
                lport = 161;
        	}

	if (communityString == (CCharPtrType) 0) {
		communityString = (CCharPtrType) "public";
	}

	cmdInit ();

	s = socket (AF_INET, SOCK_DGRAM, 0);
	if (s < 0) {
		(void) perror ("socket");
		return (1);
	}

	sin = (struct sockaddr_in *) & salocal;
        bzero ((char *) sin, sizeof (salocal));
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = lhost;
	sin->sin_port = lport;

	result = bind (s, & salocal, sizeof (*sin));
	if (result < 0) {
		(void) perror ("bind");
		return (1);
	}

	communityId = apsNew ((ApsNameType) communityString,
		(ApsNameType) "trivial", (ApsGoodiesType) 0);

	sin = (struct sockaddr_in *) & saremote;

	do {
		salen = sizeof (saremote);
		result = recvfrom (s, (char *) buf, (int) cmdBufferSize,
			(int) 0, & saremote, & salen);
		DEBUG1 ("Recvfrom: %d\n", result);
		DEBUGBYTES (buf, result);
		DEBUG0 ("\n");

		udp = udpNew (s, sin->sin_addr.s_addr, sin->sin_port);
		smp = smpNew (udp, udpSend, myUpCall);

		for (bp = buf; ((result > 0) &&
			(smpInput (smp, *bp++) == errOk));
			result--);

		smp = smpFree (smp);
		udp = udpFree (udp);

	} while (result >= 0);

	(void) perror ("recv");
	communityId = apsFree (communityId);
	return (close (s));
}


int	main (argc, argv)

int	argc;
char	*argv [];

{

  /* signal handler */
  signal(SIGINT, done);
  signal(SIGTERM, done);
  signal(SIGHUP, done);

	exit (snmpdCommand (argc, argv));
}

