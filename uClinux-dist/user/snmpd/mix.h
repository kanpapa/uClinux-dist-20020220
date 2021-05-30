#ifndef		_MIX_H_
#define		_MIX_H_

#include	"ctypes.h"
#include	"error.h"
#include	"asn.h"
#include	"smp.h"

typedef		CUnswType		MixIdType;

typedef		CUnswType		MixCookieType;

typedef		CByteType		MixNameType;

typedef		MixNameType		*MixNamePtrType;

typedef		CUnsfType		MixLengthType;

typedef		MixLengthType		*MixLengthPtrType;

typedef		SmpErrorType		MixStatusType;

typedef		MixStatusType		(*MixReleaseOpType) ();

typedef		AsnIdType		(*MixNextOpType) ();

typedef		AsnIdType		(*MixGetOpType) ();

typedef		MixStatusType		(*MixSetOpType) ();

typedef		MixStatusType		(*MixCreateOpType) ();

typedef		MixStatusType		(*MixDestroyOpType) ();

typedef		struct			MixOpsTag {

		MixReleaseOpType	mixOpsReleaseOp;
		MixCreateOpType		mixOpsCreateOp;
		MixDestroyOpType	mixOpsDestroyOp;
		MixNextOpType		mixOpsNextOp;
		MixGetOpType		mixOpsGetOp;
		MixSetOpType		mixOpsSetOp;

		}			MixOpsType;

typedef		MixOpsType		*MixOpsPtrType;

#define         mixValueAsnTag          ((AsnTagType) 0x99)
#define         mixValueAsnClass        (asnClassApplication)

#define         mixMaxPathLen        	(32)

CVoidType	mixInit ();
MixIdType	mixNew ();
MixIdType	mixFree ();
AsnIdType	mixValue ();

MixStatusType	mixCreate ();
MixStatusType	mixDestroy ();
MixStatusType	mixSet ();
AsnIdType	mixNext ();
AsnIdType	mixGet ();

#endif		/*	_MIX_H_	*/
