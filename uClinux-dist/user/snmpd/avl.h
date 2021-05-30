#ifndef		_AVL_H_
#define		_AVL_H_

#include	"ctypes.h"
#include	"error.h"

typedef		ErrStatusType		AvlStatusType;

typedef		CUnswType		AvlIdType;

typedef		enum			AvlBalanceTag {

		avlDirBalanced,
		avlDirLeft,
		avlDirRight

		}			AvlBalanceType;

typedef		AvlBalanceType		(*AvlCmpFnType) ();

typedef		AvlStatusType		(*AvlPrintFnType) ();

typedef		CUnswType		AvlInfoType;

typedef		CByteType		AvlNameType;

typedef		AvlNameType		*AvlNamePtrType;

typedef		CUnsfType		AvlLengthType;

AvlIdType	avlNew ();
AvlIdType	avlFree ();
AvlStatusType	avlInsert ();
AvlStatusType	avlRemove ();
AvlInfoType	avlFind ();
AvlInfoType	avlCessor ();
CVoidType	avlInit ();

#endif		/*	_AVL_H_	*/
