#ifndef		_ASN_H_
#define		_ASN_H_

#include	"ctypes.h"

typedef		CUnswType		AsnIdType;

typedef		CUnswType		AsnLanguageType;

typedef		CUnslType		AsnTagType;

typedef		CIntsType		AsnLengthType;

#define		asnLengthIndef		((AsnLengthType) -1)

typedef		CUnssType		AsnIndexType;

typedef		CIntlType		AsnNumberType;

typedef		enum			AsnStatusTag {

		asnStatusOk,
		asnStatusAccept,
		asnStatusReject,
		asnStatusBad

		}			AsnStatusType;

typedef		enum			AsnClassTag {

		asnClassUniversal,
		asnClassApplication,
		asnClassContext,
		asnClassPrivate

		}			AsnClassType;

typedef		enum			AsnTypeTag {

		asnTypeNone,
		asnTypeInteger,
		asnTypeOctetString,
		asnTypeObjectId,
		asnTypeSequence,
		asnTypeSequenceOf,
		asnTypeNull,
		asnTypeAny

		}			AsnTypeType;

CVoidType	asnInit ();

AsnIdType	asnNew ();
AsnIdType	asnUnsl ();
AsnIdType	asnIntl ();
AsnIdType	asnOctetString ();
AsnIdType	asnObjectId ();
AsnIdType	asnSequence ();

AsnStatusType	asnDecode ();
AsnStatusType	asnAppend ();
AsnLengthType	asnEncode ();

AsnNumberType	asnNumber ();
AsnLengthType	asnContents ();

#ifdef		INLINE

#include	<asndefs.h>

#define		asnTag(asn)		(asnTagDef (asn))
#define		asnType(asn)		(asnTypeDef (asn))
#define		asnClass(asn)		(asnClassDef (asn))
#define		asnLength(asn)		(asnLengthDef (asn))
#define		asnConstructor(asn)	(asnConstructorDef (asn))
#define		asnNegative(cp, n)	(asnNegativeDef(cp, n))
#define		asnNonZero(cp, n)	(asnNonZeroDef(cp, n))
#define		asnSons(asn)		(asnSonsDef (asn))
#define		asnComponent(asn, i)	(asnComponentDef (asn, i))
#define		asnFree(asn)		(asnFreeDef (asn))
#define		asnValue(asn)		(asnValueDef (asn))

#else		/*	INLINE	*/

AsnTypeType	asnType ();
AsnTagType	asnTag ();
AsnClassType	asnClass ();
AsnLengthType	asnLength ();
CBoolType	asnConstructor ();
CBoolType	asnNegative ();
CBoolType	asnNonZero ();
AsnIndexType	asnSons ();
AsnIdType	asnComponent ();
AsnIdType	asnFree ();
CBytePtrType	asnValue ();

#endif		/*	INLINE	*/

#endif		/*	_ASN_H_	*/
