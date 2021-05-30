#ifndef		_UDP_H_
#define		_UDP_H_

#include	"ctypes.h"
#include	"smp.h"

SmpStatusType	udpSend ();
SmpSocketType	udpNew ();
SmpSocketType	udpFree ();

#endif		/*	_UDP_H_	*/
