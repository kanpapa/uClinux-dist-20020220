#ifndef		_MIV_H_
#define		_MIV_H_

#include	"ctypes.h"
#include	"mix.h"
#include	"mis.h"

typedef		struct			MivStrTag {

		CUnsfType		mivStrMaxLen;
		CUnsfType		mivStrLen;
		CBytePtrType		mivStrData;

		}			MivStrType;

typedef		MivStrType		*MivStrPtrType;

MisStatusType	mivIntlRW ();
MisStatusType	mivIntlRO ();

MisStatusType	mivUnslRW ();
MisStatusType	mivUnslRO ();

MisStatusType	mivCounterRW ();
MisStatusType	mivCounterRO ();

MisStatusType	mivGuageRW ();
MisStatusType	mivGuageRO ();

MisStatusType	mivTicksRW ();
MisStatusType	mivTicksRO ();

MisStatusType	mivStringRW ();
MisStatusType	mivStringRO ();

MisStatusType	mivIPAddrRW ();
MisStatusType	mivIPAddrRO ();

MisStatusType	mivObjectIdRW ();
MisStatusType	mivObjectIdRO ();

#endif		/*	_MIV_H_	*/
