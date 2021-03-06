

#include	"ctypes.h"
#include	"aps.h"
#include	"asn.h"


static	AsnIdType	ap0OpDecode (goodies, asn)

ApsGoodiesType		goodies;
AsnIdType		asn;

{
	goodies = goodies;
	return (asnComponent (asn, (AsnIndexType) 3));
}

static	AsnIdType	ap0OpEncode (goodies, asn)

ApsGoodiesType		goodies;
AsnIdType		asn;

{
	AsnIndexType		i;

	goodies = goodies;
	i = (AsnIndexType) 0;
	return (asnComponent (asn, i));
}

static	CBoolType	ap0OpVerify (asn)

AsnIdType		asn;

{
	asn = asn;
	return (TRUE);
}

CVoidType		ap0Init ()

{
	(void) apsScheme ((ApsNameType) "trivial",
		ap0OpVerify, ap0OpEncode, ap0OpDecode);
}

