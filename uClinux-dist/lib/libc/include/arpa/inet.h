#ifndef __ARPA_INET_H
#define __ARPA_INET_H

#include <netinet/in.h>


__BEGIN_DECLS

int inet_aton(const char *cp, struct in_addr *inp);
      
unsigned long int inet_addr(const char *cp);

char *inet_ntoa(struct in_addr in);

/* Make Internet host address in network byte order by combining the
   network number NET with the local address HOST.  */
extern struct in_addr inet_makeaddr (u_int32_t __net, u_int32_t __host);

/* Return the local host address part of the Internet address in IN.  */
extern u_int32_t inet_lnaof (struct in_addr __in);

__END_DECLS
       
#endif
