#ifndef		_SMX_H_
#define		_SMX_H_

#include	"ctypes.h"
#include	"smp.h"

CCharPtrType		smxErrorToText ();
SmpErrorType		smxTextToError ();

CCharPtrType		smxKindToText ();
SmpKindType		smxTextToKind ();

CIntfType		smxValueToText ();
CIntfType		smxTextToValue ();

#define			smxNameToText(text, n, name, m)	\
				(smxObjectIdToText ((text), (n), (name), (m)))
#define			smxTextToName(name, m, text)	\
				(smxObjectIdToText ((name), (m), (text)))

CIntfType		smxIPAddrToText ();
CIntfType		smxTextToIPAddr ();

CIntfType		smxOctetStringToText ();
CIntfType		smxTextToOctetString ();

CIntfType		smxObjectIdToText ();
CIntfType		smxTextToObjectId ();

CIntfType		smxIntegerToText ();
CIntfType		smxTextToInteger ();

CIntfType		smxCounterToText ();
CIntfType		smxTextToCounter ();

CIntfType		smxGuageToText ();
CIntfType		smxTextToGuage ();

#endif		/*	_SMX_H_		*/
