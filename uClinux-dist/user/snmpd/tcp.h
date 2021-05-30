#ifndef		_TCP_H_
#define		_TCP_H_

#include	"ctypes.h"
#include	"smp.h"

SmpStatusType	tcpSend ();
SmpSocketType	tcpNew ();
SmpSocketType	tcpFree ();

#endif		/*	_TCP_H_	*/
