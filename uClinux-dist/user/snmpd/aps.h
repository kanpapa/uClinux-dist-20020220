#ifndef		_APS_H_
#define		_APS_H_


#include	"ctypes.h"
#include	"error.h"
#include	"asn.h"

typedef		ErrStatusType		ApsStatusType;

typedef		CUnswType		ApsIdType;

typedef		CBytePtrType		ApsNameType;

typedef		CUnswType		ApsGoodiesType;

typedef		CBoolType		(*ApsVerifyFnType) ();

typedef		AsnIdType		(*ApsEncodeFnType) ();

typedef		AsnIdType		(*ApsDecodeFnType) ();

ApsStatusType	apsScheme ();
ApsIdType	apsNew ();
ApsIdType	apsFree ();
ApsIdType	apsVerify ();
AsnIdType	apsEncode ();
AsnIdType	apsDecode ();
CVoidType	apsInit ();

#endif		/*	_APS_H_	*/
