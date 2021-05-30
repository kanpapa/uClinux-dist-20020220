#ifndef		_ASL_H_
#define		_ASL_H_


#include        "asn.h"

typedef		CUnswType		AslIdType;

AslIdType	aslLanguage ();
AslIdType	aslChoice ();
AslIdType	aslAny ();
CVoidType	aslInit ();

#ifdef		INLINE

#include	"asldefs.h"

#define		aslSon(n)		aslSonDef(n)
#define		aslKind(n)		aslKindDef(n)
#define		aslMinLen(n)		aslMinLenDef(n)
#define		aslNext(n)		aslNextDef(n)

#else		/*	INLINE		*/

AsnTypeType	aslKind ();
AslIdType	aslSon ();
AslIdType	aslNext ();
AsnLengthType	aslMinLen ();

#endif		/*	INLINE		*/

#endif		/*	_ASL_H_		*/
