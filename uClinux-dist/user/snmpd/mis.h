#ifndef		_MIS_H_
#define		_MIS_H_

#include	"ctypes.h"
#include	"error.h"
#include	"mix.h"
#include	"aps.h"

typedef		ErrStatusType		MisStatusType;

typedef		CBoolType		MisAccessType;

CVoidType	misInit ();
MisStatusType	misExport ();
MisAccessType	misCommunityToAccess ();
MixIdType	misCommunityToMib ();
ApsIdType	misCommunityByName ();

#endif		/*	_MIS_H_	*/
