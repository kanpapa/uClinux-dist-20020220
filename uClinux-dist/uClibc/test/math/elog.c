/*						xlog.c	*/
/* natural logarithm */
/* by Stephen L. Moshier. */

#include "mconf.h"
#include "ehead.h"



void elog( x, y )
unsigned short *x, *y;
{
unsigned short xx[NE], z[NE], a[NE], b[NE], t[NE], qj[NE];
long ex;
int fex;


if( x[NE-1] & (unsigned short )0x8000 )
	{
	eclear(y);
	mtherr( "elog", DOMAIN );
	return;
	}
if( ecmp( x, ezero ) == 0 )
	{
	einfin( y );
	eneg(y);
	mtherr( "elog", SING );
	return;
	}
if( ecmp( x, eone ) == 0 )
	{
	eclear( y );
	return;
	}

/* range reduction: log x = log( 2**ex * m ) = ex * log2 + log m */
efrexp( x, &fex, xx );
/*
emov(x, xx );
ex = xx[NX-1] & 0x7fff;
ex -= 0x3ffe;
xx[NX-1] = 0x3ffe;
*/

/* Adjust range to 1/sqrt(2), sqrt(2) */
esqrt2[NE-1] -= 1;
if( ecmp( xx, esqrt2 ) < 0 )
	{
	fex -= 1;
	emul( xx, etwo, xx );
	}
esqrt2[NE-1] += 1;

esub( eone, xx, a );
if( a[NE-1] == 0 )
	{
	eclear( y );
	goto logdon;
	}
eadd( eone, xx, b );
ediv( b, a, y );	/* store (x-1)/(x+1) in y */

emul( y, y, z );

emov( eone, a );
emov( eone, b );
emov( eone, qj );
do
	{
	eadd( etwo, qj, qj );	/* 2 * i + 1		*/
	emul( z, a, a );
	ediv( qj, a, t );
	eadd( t, b, b );
	}
while( ((b[NE-1] & 0x7fff) - (t[NE-1] & 0x7fff)) < NBITS );


emul( b, y, y );
emul( y, etwo, y );

logdon:

/* now add log of 2**ex */
if( fex != 0 )
	{
	ex = fex;
	ltoe( &ex, b );
	emul( elog2, b, b );
	eadd( b, y, y );
	}
}
