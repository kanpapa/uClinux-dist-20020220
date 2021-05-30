#ifndef		_ASX_H_
#define		_ASX_H_

#include	"ctypes.h"
#include	"error.h"
#include	"asn.h"

typedef		ErrStatusType		AsxStatusType;

AsxStatusType	asxPrint ();
CBytePtrType	asxTypeToLabel ();
CVoidType	asxInit ();

#endif		/*	_ASX_H_	*/
