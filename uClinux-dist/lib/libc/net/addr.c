/* Copyright (C) 1995,1996 Robert de Bath <rdebath@cix.compulink.co.uk>
 * This file is part of the Linux-8086 C library and is distributed
 * under the GNU Library General Public License.
 */

#include <string.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#ifdef L_inet_aton
int
inet_aton(cp, inp)
const char *cp;
struct in_addr *inp;
{
  unsigned long addr;
  int value;
  int part;

  if (!inp)
    return 0;
  
  addr = 0;
  for (part=1;part<=4;part++) {

    if (!isdigit(*cp))
      return 0;
        
    value = 0;
    while (isdigit(*cp)) {
      value *= 10;
      value += *cp++ - '0';
      if (value > 255)
        return 0;
    }
    
    if (*cp++ != ((part == 4) ? '\0' : '.'))
      return 0;
    
    addr <<= 8;
    addr |= value;
  }
  
  inp->s_addr = htonl(addr);

  return 1;
}
#endif

#ifdef L_inet_addr
unsigned long
inet_addr(cp)
const char *cp;
{
  struct in_addr a;
  if (!inet_aton(cp, &a))
    return -1;
  else
    return a.s_addr;
}
#endif

#ifdef L_inet_ntoa

extern char * itoa(int);  

char *
inet_ntoa(in)
struct in_addr in;
{
  static char buf[18];
  unsigned long addr = ntohl(in.s_addr);
  
  strcpy(buf, itoa((addr >> 24) & 0xff));
  strcat(buf, ".");
  strcat(buf, itoa((addr >> 16) & 0xff));
  strcat(buf, ".");
  strcat(buf, itoa((addr >> 8) & 0xff));
  strcat(buf, ".");
  strcat(buf, itoa(addr & 0xff));
  
  return buf;
}

#endif

#ifdef L_inet_ntop

char *
inet_ntop(af, src, dst, cnt)
int af;
const void *src;
char *dst;
size_t cnt;
{
  char *lp;
  if (af == AF_INET) {
	lp = inet_ntoa(*((struct in_addr *) src));
	memcpy(dst, lp, cnt);
#ifdef AF_INET6
  } else if (af == AF_INET6) {
	memcpy(dst, "AF_INET6", cnt);
#endif
  } else {
	dst = NULL;
  }
  return(dst);
}

#endif

#if L_inet_mkadr

/*
 * Formulate an Internet address from network + host.  Used in
 * building addresses stored in the ifnet structure.
 */
struct in_addr
inet_makeaddr(net, host)
        u_int32_t net, host;
{
        u_int32_t addr;

        if (net < 128)
                addr = (net << IN_CLASSA_NSHIFT) | (host & IN_CLASSA_HOST);
        else if (net < 65536)
                addr = (net << IN_CLASSB_NSHIFT) | (host & IN_CLASSB_HOST);
        else if (net < 16777216L)
                addr = (net << IN_CLASSC_NSHIFT) | (host & IN_CLASSC_HOST);
        else
                addr = net | host;
        addr = htonl(addr);
        return (*(struct in_addr *)&addr);
}

#endif

#if L_inet_lnaof
/*
 * Return the local network address portion of an
 * internet address; handles class a/b/c network
 * number formats.
 */
u_int32_t
inet_lnaof(in)
	struct in_addr in;
{
	u_int32_t i = ntohl(in.s_addr);

	if (IN_CLASSA(i))
		return ((i)&IN_CLASSA_HOST);
	else if (IN_CLASSB(i))
		return ((i)&IN_CLASSB_HOST);
	else
		return ((i)&IN_CLASSC_HOST);
}
#endif

#ifdef L_inet_netof

/*
 * Return the network number from an internet
 * address; handles class a/b/c network #'s.
 */
u_int32_t
inet_netof(in)
        struct in_addr in;
{
        u_int32_t i = ntohl(in.s_addr);

        if (IN_CLASSA(i))
                return (((i)&IN_CLASSA_NET) >> IN_CLASSA_NSHIFT);
        else if (IN_CLASSB(i))
                return (((i)&IN_CLASSB_NET) >> IN_CLASSB_NSHIFT);
        else
                return (((i)&IN_CLASSC_NET) >> IN_CLASSC_NSHIFT);
}

#endif
