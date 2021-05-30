/* dnsmasq is Copyright (c) 2000 Simon Kelley

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
*/

/* See RFC1035 for details of the protocol this code talks. */

/* Author's email: simon@thekelleys.org.uk */

#define VERSION "0.992"

#define FTABSIZ 100 /* max number of outstanding requests */
#ifdef __uClinux__
#define CACHESIZ 20 /* default cache size */
#define HOSTSFILE "/etc/config/hosts"
#define RESOLVFILE "/etc/config/resolv.conf"
#else
#define CACHESIZ 300 /* default cache size */
#define HOSTSFILE "/etc/hosts"
#define RESOLVFILE "/etc/resolv.conf"
#endif
#define MAXLIN 1024 /* line length in config files */
#define RUNFILE "/var/run/dnsmasq.pid"

#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <net/if.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <ctype.h>
#include <signal.h>
#include <syslog.h>
#include <getopt.h>
#include <time.h>
#include <errno.h>

struct crec { 
  char name[MAXDNAME];
  struct in_addr addr;
  struct crec *next, *prev;
  time_t ttd; /* time to die */
  int flags;
};

#define F_IMMORTAL 1
#define F_NEW 2
#define F_REVERSE 4
#define F_FORWARD 8

struct server {
  struct sockaddr_in addr;
  struct server *next; /* circle */
};

/* linked list of all the interfaces in the system and 
   the sockets we have bound to each one. */
struct irec {
  struct sockaddr_in addr;
  int fd;
  struct irec *next;
};

struct frec {
  struct sockaddr source;
  struct server *sentto;
  unsigned short orig_id, new_id;
  int fd;
  time_t time;
};

static void cache_insert(struct crec *crecp);
static struct crec *cache_get_free(void);
static void cache_unlink (struct crec *crecp);
static int process_request(HEADER *header, char *limit, int qlen);
static int do_reverse_lookup(char *name, unsigned int nameoffset,
			     char *limit, unsigned char **anspp);
static int do_forward_lookup(char *name, unsigned int nameoffset,
			     char *limit, unsigned char **anspp);
static int do_mx_lookup(char *name, unsigned int nameoffset,
			char *limit, unsigned char **anspp);
static void do_one_query(int udpfd, 
			 int peerfd,
			 struct sockaddr *udpaddr, 
			 HEADER *header,
			 int plen);
static void reload_cache(int use_hosts, int cachesize);
static void reload_servers(char *fname, struct irec *interfaces, int port);
static struct irec *find_all_interfaces(int fd);
static void sig_hangup(int sig);
static struct frec *get_new_frec(time_t now);
static struct frec *lookup_frec(unsigned short id);
static struct frec *lookup_frec_by_sender(unsigned short id,
					  struct sockaddr *addr);
static unsigned short get_id(void);
static void extract_addresses(HEADER *header, int qlen);
static struct crec *cache_find_by_addr(struct crec *crecp, struct in_addr addr, time_t now);
static struct crec *cache_find_by_name(struct crec *crecp, char *name, time_t now);
static void cache_mark_all_old(void);
static void cache_remove_old_name(char *name, time_t now);
static void cache_remove_old_addr(struct in_addr addr, time_t now);
static void cache_name_insert(char *name, struct in_addr addr, time_t ttd);
static void cache_addr_insert(char *name, struct in_addr addr, time_t ttd);
static void cache_host_insert(struct crec *crecp, char *name, struct in_addr addr);
static int private_net(struct in_addr addr);
static unsigned char *add_text_record(unsigned int nameoffset, unsigned char *p, unsigned short ttl, 
				      unsigned short pref, unsigned short type, char *name);

static struct crec *cache_head, *cache_tail;
static struct server *last_server;  
static struct frec *ftab;

static int sighup;
static char *mxname;
static int boguspriv;

int main (int argc, char **argv)
{
  int i, cachesize = CACHESIZ;
  struct crec *crecp;
  int port = NAMESERVER_PORT;
  int peerfd, option; 
  int use_hosts = 1, daemon = 1;
  char *resolv = RESOLVFILE;
  struct stat statbuf;
  time_t resolv_changed = 0;
  struct irec *iface, *interfaces = NULL;
  FILE *pidfile;

  sighup = 1; /* init cache the first time through */
  mxname = NULL;
  boguspriv = 0;

  last_server = NULL;
  
  opterr = 0;

  while (1)
    {
      option = getopt(argc, argv, "bvhdr:m:p:c:");
      
      if (option == 'b')
	  boguspriv = 1;
	
      if (option == 'v')
	{
	  fprintf(stderr, "dnsmasq version %s\n", VERSION);
	  exit(0);
	}

      if (option == 'h')
	use_hosts = 0;

      if (option == 'd')
	daemon = 0;
      
      if (option == 'r')
	{
	  resolv = malloc(strlen(optarg)+1);
	  strcpy(resolv, optarg);
	}

      if (option == 'm')
	{
	  mxname = malloc(strlen(optarg)+1);
	  strcpy(mxname, optarg);
	}

      if (option == 'c')
	{
	  cachesize = atoi(optarg);
	  /* zero is OK, and means no cacheing.
	     Very low values cause prolems with  hosts
	     with many A records. */
	  
	  if (cachesize < 0)
	    option = '?'; /* error */
	  else if ((cachesize > 0) && (cachesize < 20))
	    cachesize = 20;
	  else if (cachesize > 1000)
	    cachesize = 1000;
	}

      if (option == 'p')
	port = atoi(optarg);
      
      if (option == '?')
	{ 
	  fprintf(stderr, 
		  "Usage: dnsmasq -b -v -d -h -r <resolv.conf> -p "
		  "<port> -m <mxhost> -c <cachesize>\n");
	  exit(0);
	}
      
      if (option == -1)
	break;
    }

  /* peerfd is not bound to a low port
     so that we can send queries out on it without them getting
     blocked at firewalls */
  
  if ((peerfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
      perror("dnsmasq: cannot create socket");
      exit(1);
    }
  
  interfaces = find_all_interfaces(peerfd);

  /* open a socket bound to NS port on each local interface.
     this is necessary to ensure that our replies originate from
     the address they were sent to. See Stevens page 531 */
  for (iface = interfaces; iface; iface = iface->next)
    {
      iface->addr.sin_port = htons(port);
      if ((iface->fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
	{
	  perror("dnsmasq: cannot create socket");
	  exit(1);
	}
      
      if (bind(iface->fd, 
	       (struct sockaddr *)&iface->addr, sizeof(iface->addr)))
	{
	  perror("dnsmasq: bind failed");
	  exit(1);
	}
    }

  ftab = (struct frec *)malloc(FTABSIZ*sizeof(struct frec));
  crecp = (struct crec *)malloc(cachesize*sizeof(struct crec));
  
  if (!ftab || !crecp)
    {
      fprintf(stderr, "dnsmasq: could not get memory");
      exit(1);
    }

  for (i=0; i<FTABSIZ; i++)
    ftab[i].new_id = 0;
  
  cache_head = NULL;
  cache_tail = crecp;
  for (i=0; i<cachesize; i++, crecp++)
    cache_insert(crecp);

  if (daemon)
    {
      /* The following code "daemonizes" the process. 
	 See Stevens section 12.4 */

#ifndef __uClinux__
      if (fork() != 0 )
	exit(0);
#endif
      
      setsid();
      
#ifndef __uClinux__
      if (fork() != 0)
	exit(0);
#endif
      
      chdir("/");

      for (i=0; i<64; i++)
	{
	  if (i == peerfd)
	    continue;
	  for (iface = interfaces; iface; iface = iface->next)
	    if (iface->fd == i)
	      break;
	  if (!iface)
	    close(i);
	}

    }

  umask(022); /* make pidfile 0644 */
      
  /* write pidfile _after_ forking ! */
  if ((pidfile = fopen(RUNFILE, "w")))
    {
      fprintf(pidfile, "%d\n", getpid());
      fclose(pidfile);
    }
      
  umask(0);

  openlog("dnsmasq", LOG_PID, LOG_DAEMON);
  
  if (cachesize)
    syslog(LOG_INFO, "started, version %s cachesize %d", VERSION, cachesize);
  else
    syslog(LOG_INFO, "started, version %s cache disabled", VERSION);
  if (mxname)
    syslog(LOG_INFO, "serving MX record for mailhost %s", mxname);
    
#if 1
  for (iface = interfaces; iface; iface = iface->next)
    {
      iface->addr.sin_port = htons(port);
      syslog(LOG_INFO, "initial bind to %s", inet_ntoa(iface->addr.sin_addr));
    }
#endif

  while (1)
    {
      /* Size: we check after adding each record, so there must be 
	 memory for the largest packet, and the largest record */
      char packet[PACKETSZ+MAXDNAME+RRFIXEDSZ];
      int n, maxfd = peerfd;
      fd_set rset;
      HEADER *header;

      FD_ZERO(&rset);
      FD_SET(peerfd, &rset);
      for (iface = interfaces; iface; iface = iface->next)
	{
	  FD_SET(iface->fd, &rset);
	  if (iface->fd > maxfd)
	    maxfd = iface->fd;
	}
      
      if (select(maxfd+1, &rset, NULL, NULL, NULL) == -1)
	continue;

      if (sighup)
	{
	  signal(SIGHUP, SIG_IGN);
	  reload_cache(use_hosts, cachesize);
	  sighup = 0;
	  signal(SIGHUP, sig_hangup);
	}
      
      if ((stat(resolv, &statbuf) == 0) && 
	  (statbuf.st_mtime > resolv_changed) &&
	  (statbuf.st_mtime < time(NULL)))
	{
	  resolv_changed = statbuf.st_mtime;
	  reload_servers(resolv, interfaces, port);
	}

      if (FD_ISSET(peerfd, &rset))
	{
	  /* packet from peer server, extract data for cache, and send to
	     original requester */
	  n = recvfrom(peerfd, packet, PACKETSZ, 0, NULL, NULL);
 
	  header = (HEADER *)packet;
	  if (n >= sizeof(HEADER) && header->qr)
	    {
	      struct frec *forward = lookup_frec(ntohs(header->id));
	      if (forward)
		{
		  last_server = forward->sentto; /* known good */
		  if (cachesize != 0 && header->opcode == QUERY && header->rcode == NOERROR)
		    extract_addresses(header, n);
		  header->id = htons(forward->orig_id);
		  sendto(forward->fd, packet, n, 0, 
			 &forward->source, sizeof(forward->source));
		  forward->new_id = 0; /* cancel */
		}
	    }
	}
      
      for (iface = interfaces; iface; iface = iface->next)
	{
	  if (FD_ISSET(iface->fd, &rset))
	    {
	      /* request packet, deal with query */
	      struct sockaddr udpaddr;
	      socklen_t udplen;
	      udplen = sizeof(udpaddr);
	      n = recvfrom(iface->fd, packet, PACKETSZ, 0, &udpaddr, &udplen); 
	      /* DS: Kernel 2.2.x complains if AF_INET isn't set */
	      ((struct sockaddr_in *)&udpaddr)->sin_family = AF_INET;
	      
	      header = (HEADER *)packet;
	      if (n >= sizeof(HEADER) && !header->qr)
		do_one_query(iface->fd, peerfd, &udpaddr, header, n);
	    }
	}
    }
  return 0;

}

static struct irec *find_all_interfaces(int fd)
{
  /* this code is adapted from Stevens, page 434. It finally
     destroyed my faith in the C/unix API */
  int len = 100 * sizeof(struct ifreq);
  int lastlen = 0;
  char *buf, *ptr;
  struct ifconf ifc;
  struct irec *ret = NULL;

  while (1)
    {
      buf = malloc(len);
      if (!buf)
	{
	  fprintf(stderr, "dnsmasq: could not get memory");
	  exit(1);
	}
      ifc.ifc_len = len;
      ifc.ifc_buf = buf;
      if (ioctl(fd, SIOCGIFCONF, &ifc) < 0)
	{
	  if (errno != EINVAL || lastlen != 0)
	    {
	      perror("dnsmasq: ioctl error while enumerating interfaces");
	      exit(1);
	    }
	}
      else
	{
	  if (ifc.ifc_len == lastlen)
	    break; /* got a big enough buffer now */
	  lastlen = ifc.ifc_len;
	}
      len += 10* sizeof(struct ifreq);
      free(buf);
    }

  for (ptr = buf; ptr < buf + ifc.ifc_len; ptr += sizeof(struct ifreq))
    {
      struct ifreq *ifr = (struct ifreq *) ptr;
      
      if (ifr->ifr_addr.sa_family == AF_INET)
	{
	  struct irec *iface;
	  
	  /* first check whether the interface IP has been added already 
	     it is possible to have multiple interface with the same address. */
	  for (iface = ret; iface; iface = iface->next) 
	    if (memcmp(&iface->addr, &ifr->ifr_addr, sizeof(struct sockaddr)) == 0)
	      break;
	  if (iface) 
	    continue;
	  
	  /* If not, add it to the head of the list */
	  iface = malloc(sizeof(struct irec));
	  if (!iface)
	    {
	      fprintf(stderr, "dnsmasq: could not get memory");
	      exit(1);
	    }
	  iface->addr = *((struct sockaddr_in *)&ifr->ifr_addr);
	  iface->next = ret;
	  ret = iface;
	}
    }
     
  free(buf);
  return ret;
}

static void sig_hangup(int sig)
{
  sighup = 1;
}

static void reload_servers(char *fname, struct irec *interfaces, int port)
{
  FILE *f;
  char *line, buff[MAXLIN];
  int i;

  f = fopen(fname, "r");
  if (!f)
    {
      syslog(LOG_ERR, "failed to read %s: %m", fname);
      return;
    }
  
  syslog(LOG_INFO, "reading %s", fname);

  /* forward table rules reference servers, so have to blow 
     them away */
  for (i=0; i<FTABSIZ; i++)
    ftab[i].new_id = 0;
  
  /* delete existing ones */
  if (last_server)
    {
      struct server *s = last_server;
      while (1)
	{
	  struct server *tmp = s->next;
	  free(s);
	  if (tmp == last_server)
	    break;
	  s = tmp;
	}
      last_server = NULL;
    }
	
  while ((line = fgets(buff, MAXLIN, f)))
    {
      struct in_addr addr;
      char *token = strtok(line, " \t\n");
      struct server *serv;
      struct irec *iface;

      if (!token || strcmp(token, "nameserver") != 0)
	continue;
      if (!(token = strtok(NULL, " \t\n")) || !inet_aton(token, &addr))
	continue;
      
      /* Avoid loops back to ourself */
      if (port == NAMESERVER_PORT)
	{
	  for (iface = interfaces; iface; iface = iface->next)
	    if (addr.s_addr == iface->addr.sin_addr.s_addr)
	      {
		syslog(LOG_WARNING, "ignoring nameserver %s - local interface",
		       inet_ntoa(addr));
		break;
	      }
	  if (iface)
	    continue;
	}

      if (!(serv = (struct server *)malloc(sizeof (struct server))))
	continue;

      if (last_server)
	last_server->next = serv;
      else
	last_server = serv;
      
      serv->next = last_server;
      last_server = serv;

      serv->addr.sin_family = AF_INET;
      serv->addr.sin_port = htons(NAMESERVER_PORT);
      serv->addr.sin_addr = addr;
      syslog(LOG_INFO, "using nameserver %s", inet_ntoa(addr)); 
    }
  
  fclose(f);
}
	
static void reload_cache(int use_hosts, int cachesize)
{
  struct crec *cache;
  FILE *f;
  char *line, buff[MAXLIN];

  for (cache=cache_head; cache; cache = cache->next)
    if (cache->flags & F_IMMORTAL)
      {
	cache_unlink(cache);
	free(cache);
      }
    else
      cache->flags = 0;
  
  if (!use_hosts && (cachesize > 0))
    {
      syslog(LOG_INFO, "cleared cache");
      return;
    }
  
  f = fopen(HOSTSFILE, "r");
  
  if (!f)
    {
      syslog(LOG_ERR, "failed to load names from %s: %m", HOSTSFILE);
      return;
    }
  
  syslog(LOG_INFO, "reading %s", HOSTSFILE);
  
  while ((line = fgets(buff, MAXLIN, f)))
    {
      struct in_addr addr;
      char *token = strtok(line, " \t\n");
          
      if (!token || (*token == '#') || !inet_aton(token, &addr))
	continue;
      
      while ((token = strtok(NULL, " \t\n")) && (*token != '#'))
	if ((cache = (struct crec *) malloc(sizeof(struct crec))))
	  cache_host_insert(cache, token, addr);
    }

  fclose(f);
}
  
static void do_one_query(int udpfd,
			 int peerfd,
			 struct sockaddr *udpaddr, 
			 HEADER *header,
			 int plen)
{
  int m;
  time_t now = time(NULL);
  struct frec *forward;
  
  if (header->opcode == QUERY &&
      (m = process_request(header, ((char *)header) + PACKETSZ, plen)))
    {
      /* answered from cache, send reply */
      sendto(udpfd, (char *)header, m, 0, 
	     udpaddr, sizeof(struct sockaddr));
      return;
    }
  
  /* cannot answer from cache, send on to real nameserver */
  
  /* may be no available servers or recursion not speced */
  if (!last_server || !header->rd)
    forward = NULL;
  else if ((forward = lookup_frec_by_sender(ntohs(header->id), udpaddr)))
    {
      /* retry on existing query, send to next server */
      forward->sentto = forward->sentto->next;
      header->id = htons(forward->new_id);
    }
  else
    {
      /* new query, pick nameserver and send */
      forward = get_new_frec(now);
      forward->source = *udpaddr;
      forward->new_id = get_id();
      forward->fd = udpfd;
      forward->orig_id = ntohs(header->id);
      header->id = htons(forward->new_id);
      forward->sentto = last_server;
      last_server = last_server->next;
    }

  /* check for sendto errors here (no route to host) 
     if we fail to send to all nameservers, send back an error
     packet straight away (helps modem users when offline) */
  
  if (forward)
    {
      struct server *firstsentto = forward->sentto;
      while (1)
	{ 
	  if (sendto(peerfd, (char *)header, plen, 0, 
		     (struct sockaddr *)&forward->sentto->addr, 
		     sizeof(forward->sentto->addr)) != -1)
	    return;
	  
	  forward->sentto = forward->sentto->next;
	  /* check if we tried all without success */
	  if (forward->sentto == firstsentto)
	    break;
	}
      
      /* could not send on, prepare to return */ 
      header->id = htons(forward->orig_id);
      forward->new_id = 0; /* cancel */
    }	  
  
  /* could not send on, return empty answer */
  header->qr = 1; /* response */
  header->aa = 0; /* authoritive - never */
  header->ra = 1; /* recursion if available */
  header->tc = 0; /* not truncated */
  header->rcode = NOERROR; /* no error */
  header->ancount = htons(0); /* no answers */
  header->nscount = htons(0);
  header->arcount = htons(0);
  sendto(udpfd, (char *)header, plen, 0, 
	 udpaddr, sizeof(struct sockaddr));
}

static struct frec *get_new_frec(time_t now)
{
  int i;
  struct frec *oldest = &ftab[0];
  time_t oldtime = now;

  for(i=0; i<FTABSIZ; i++)
    {
      struct frec *f = &ftab[i];
      if (f->time <= oldtime)
	{
	  oldtime = f->time;
	  oldest = f;
	}
      if (f->new_id == 0)
	{
	  f->time = now;
	  return f;
	}
    }

  /* table full, use oldest */

  oldest->time = now;
  return oldest;
}
 
static struct frec *lookup_frec(unsigned short id)
{
  int i;
  for(i=0; i<FTABSIZ; i++)
    {
      struct frec *f = &ftab[i];
      if (f->new_id == id)
	return f;
    }
  return NULL;
}

static struct frec *lookup_frec_by_sender(unsigned short id,
					  struct sockaddr *addr)
{
  int i;
  for(i=0; i<FTABSIZ; i++)
    {
      struct frec *f = &ftab[i];
      if (f->new_id &&
	  f->orig_id == id && 
	  memcmp(&f->source, addr, sizeof(f->source)) == 0)
	return f;
    }
  return NULL;
}


/* return unique ids between 1 and 65535 */
/* These are now random, FSVO random, to frustrate DNS spoofers */
/* code adapted from glibc-2.1.3 */ 
static unsigned short get_id(void)
{
  struct timeval now;
  static int salt = 0;
  unsigned short ret = 0;

  /* salt stops us spinning wasting cpu on a host with
     a low resolution clock and avoids sending requests
     with the same id which are close in time. */

  while (ret == 0)
    {
      gettimeofday(&now, NULL);
      ret = salt-- ^ now.tv_sec ^ now.tv_usec ^ getpid();
      
      /* scrap ids already in use */
      if ((ret != 0) && lookup_frec(ret))
	ret = 0;
    }

  return ret;
}

static int extract_name(HEADER *header, int plen, unsigned char **pp, char *name)
{
  char *cp = name;
  unsigned char *p = *pp, *p1 = NULL;
  int j, hops=0;
  unsigned int l;
    
  while ((l = *p++))
    {
      if ((l & 0xc0) == 0xc0) /* pointer */
	{ 
	  if (p - (unsigned char *)header + 1 >= plen)
	    return 0;
	      
	  /* get offset */
	  l = (l&0x3f) << 8;
	  l |= *p++;
	  if (l >= plen) 
	    return 0;
	  
	  if (!p1) /* first jump, save location to go back to */
	    p1 = p;
	      
	  hops++; /* break malicious infinite loops */
	  if (hops > 255)
	    return 0;
	  
	  p = l + (unsigned char *)header;
	}
      else
	{
	  if (cp-name+l+1 >= MAXDNAME)
	    return 0;
	  if (p - (unsigned char *)header + l >= plen)
		return 0;
	  for(j=0; j<l; j++)
	    *cp++ = tolower(*p++);
	  *cp++ = '.';
	}
      if (p - (unsigned char *)header >= plen)
	return 0;
    }
  *--cp = 0; /* overwrite last period */
  
  if (p1) /* we jumped via compression */
    p = p1;
  
  if (p - (unsigned char *)header + 4 > plen)
    return 0;

  *pp = p;
  return 1;
}

static struct in_addr in_arpa_name_2_addr(char *name)
{
  int i,j;
  char *cp1;
  unsigned char addr[4];

  /* turn name into a series of asciiz strings */
  /* j counts no of labels */
  for(j = 1,cp1 = name; *cp1; cp1++)
    if (*cp1 == '.')
      {
	*cp1 = 0;
	j++;
      }
    
  addr[0] = addr[1] = addr[2] = addr[3] = 0;

  /* address arives as a name of the form
     www.xxx.yyy.zzz.in-addr.arpa
     some of the low order address octets might be missing
     and should be set to zero. */
  for (cp1 = name,i=0; i<j; i++)
    {
      if (strcmp(cp1, "in-addr") == 0)
	break;
      addr[3] = addr[2];
      addr[2] = addr[1];
      addr[1] = addr[0];
      addr[0] = atoi(cp1);
      cp1 += strlen(cp1)+1;
    }

  return *((struct in_addr *)addr);
}

static unsigned char *skip_questions(HEADER *header, int plen)
{
  int q, qdcount = ntohs(header->qdcount);
  unsigned char *ansp = (unsigned char *)(header+1);

  for (q=0; q<qdcount; q++)
    {
      while (1)
	{
          if (ansp - (unsigned char *)header >= plen)
	    return NULL;
	  if (((*ansp) & 0xc0) == 0xc0) /* pointer for name compression */
	    {
              ansp += 2;	
	      break;
	    }
	  else if (*ansp) 
	    { /* another segment */
	      ansp += (*ansp) + 1;
	    }
	  else            /* end */
	    {
	      ansp++;
	      break;
	    }
	}
      ansp += 4; /* class and type */
    }
  if (ansp - (unsigned char *)header > plen) 
     return NULL;
  
  return ansp;
}

static void extract_addresses(HEADER *header, int qlen)
{
  char name[MAXDNAME];
  unsigned char *p, *psave, *endrr;
  int qtype, qclass, ttl, rdlen;
  int ancount = ntohs(header->ancount) + ntohs(header->nscount) + ntohs(header->arcount);
  int i;
  time_t now = time(NULL);

   /* skip over questions */
  if (!(p = skip_questions(header, qlen)))
    return; /* bad packet */

  /* process answer, authority and additional sections. */
  /* there won't be any A or PTR RRs in the authority section
     but we skip it for free this way */
  
  /* Strategy: mark all entries as old and suitable for replacement.
     new entries made here are not removed while processing this packet.
     Makes multiple addresses per name work. */
  
  cache_mark_all_old();
  
  psave = p;
  
  for (i=0; i<ancount; i++)
    {
      if (!extract_name(header, qlen, &p, name))
	return; /* bad packet */

      GETSHORT(qtype, p); 
      GETSHORT(qclass, p);
      GETLONG(ttl, p);
      GETSHORT(rdlen, p);
	
      endrr = p + rdlen;
      if (endrr - (unsigned char *)header > qlen)
	return; /* bad packet */
      
      if ((qclass == C_IN) && (qtype == T_A) && (rdlen == INADDRSZ))
	{
	  /* A record. */
	  cache_remove_old_name(name, now);
	  cache_name_insert(name, *((struct in_addr *)p), ttl + now);
	}

      if ((qclass == C_IN) && (qtype == T_PTR))
	{
	  /* PTR record */
	  struct in_addr addr = in_arpa_name_2_addr(name);
	  if (!extract_name(header, qlen, &p, name))
	    return; /* bad packet */
	  cache_remove_old_addr(addr, now);
	  cache_addr_insert(name, addr, ttl + now);
	}
   
	p = endrr;
    }

  /* Now do a second pass, looking for CNAMEs. The addresses of hosts
     they refer to should be in the cache now, so we can use that
     to translate the cnames to addresses too. */
  
  p = psave;

  for (i=0; i<ancount; i++)
    {
      if (!extract_name(header, qlen, &p, name))
	return;

      GETSHORT(qtype, p); 
      GETSHORT(qclass, p);
      GETLONG(ttl, p);
      GETSHORT(rdlen, p);
      
      endrr = p+rdlen;
      if (endrr - (unsigned char *)header > qlen)
	return; /* bad packet */
      
      if ((qclass == C_IN) && (qtype == T_CNAME))
	{
	  char rname[MAXDNAME];
	  struct crec *crecp;
	  
	  if (!extract_name(header, qlen, &p, rname))
	    return; /* bad packet */
	
	  /* note that there is deep cache magic here: anybody trying to
	     re-do the cache module should ensure that the sequence of 
	     searches and insertions which happen here are still valid. */

	  cache_remove_old_name(name, now);
	  crecp = NULL; 
	  while ((crecp = cache_find_by_name(crecp, rname, now)))
	    {
	      int a_ttl = crecp->ttd - now;
	      /* use smallest ttl of cname and a records */
	      if (a_ttl < ttl)
		ttl = a_ttl;
	      
	      cache_name_insert(name, crecp->addr, ttl + now);
	    }
	}
      
      p = endrr;
    }
}
	        
/* return zero if we can't answer from cache, or packet
   size if we can */
static int process_request(HEADER *header, char *limit, int qlen)
{
  unsigned char *ansp, *p;
  int qtype, qclass;
  char name[MAXDNAME];
  unsigned int q, nameoffset;
  int qdcount = ntohs(header->qdcount); 
  int ans, anscount = 0;
  int trunc = 0;

  if (!qdcount)
    return 0;

  /* determine end of question section (we put answers there) */
  if (!(ansp = skip_questions(header, qlen)))
    return 0; /* bad packet */
   
  /* now process each question, answers go in RRs after the question */
  p = (unsigned char *)(header+1);
  for (q=0; q<qdcount; q++)
    {
      /* save pointer to name for copying into answers */
      nameoffset = p - (unsigned char *)header;

      /* now extract name as .-concatenated string into name */
      if (!extract_name(header, qlen, &p, name))
	return 0; /* bad packet */

      GETSHORT(qtype, p); 
      GETSHORT(qclass, p);
  
      /* do_*_lookup return number of answers (-ve if they ran out of room) */
      if ((qclass == C_IN) && (qtype == T_PTR))
	ans = do_reverse_lookup(name, nameoffset, limit, &ansp);
      else if ((qclass == C_IN) && (qtype == T_A))
	ans = do_forward_lookup(name, nameoffset, limit, &ansp);
      else if ((qclass == C_IN) && (qtype == T_MX))
	ans = do_mx_lookup(name, nameoffset, limit, &ansp);
      else
	ans = 0;

      if (ans == 0)
	return 0 ; /* Cannot answer a question, give up */
      
      if (ans > 0) /* good reply */
	anscount += ans;
      else
	{
	  /* truncation, don't count last one. */
	  trunc = 1;
	  anscount -= ans;
	  anscount--;
	}
    }

  /* done all questions, set up header and return length of result */
  header->qr = 1; /* response */
  header->aa = 0; /* authoritive - never */
  header->ra = 1; /* recursion if available */
  header->tc = trunc ? 1 : 0; /* truncation */
  header->rcode = NOERROR; /* no error */
  header->ancount = htons(anscount);
  header->nscount = htons(0);
  header->arcount = htons(0);
  return ansp - (unsigned char *)header;
}



static int do_forward_lookup(char *name, unsigned int nameoffset, char *limit, unsigned char **anspp)
{
  unsigned char *p = *anspp;
  time_t now = time(NULL);
  struct crec *crecp = NULL;
  int ans = 0;
  
  /* loop round multiple names */ 
  while ((crecp = cache_find_by_name(crecp, name, now)))
    { 
      /* copy question as first part of answer (use compression)*/
      
      PUTSHORT(nameoffset | 0xc000, p); 
      PUTSHORT(T_A, p);
      PUTSHORT(C_IN, p);
      PUTLONG((crecp->flags & F_IMMORTAL) ? 0 : crecp->ttd - now, p); /* TTL */
	      
      PUTSHORT(INADDRSZ, p);
      memcpy(p, &crecp->addr, INADDRSZ);
      p += INADDRSZ;
      
      ans++;

      /* if last answer exceeded packet size, give up */
      if (((unsigned char *)limit - p) < 0)
	return -ans;
	      
      *anspp = p;
    } 
  
  return ans;
}

/* is addr in the non-globally-routed IP space? */ 
static int private_net(struct in_addr addr) 
{
  if (inet_netof(addr) == 0xA ||
      (inet_netof(addr) >= 0xAC10 && inet_netof(addr) < 0xAC20) ||
     (inet_netof(addr) >> 8) == 0xC0A8) 
    return 1;
  else 
    return 0;
}
 
static unsigned char *add_text_record(unsigned int nameoffset, unsigned char *p, unsigned short ttl,
				      unsigned short pref, unsigned short type, char *name)
{
  unsigned char *sav, *cp;
  int j;
  
  PUTSHORT(nameoffset | 0xc000, p); 
  PUTSHORT(type, p);
  PUTSHORT(C_IN, p);
  PUTLONG(ttl, p); /* TTL */
  
  sav = p;
  PUTSHORT(0, p); /* dummy RDLENGTH */

  if (pref)
    PUTSHORT(pref, p);

  while (*name) 
    {
      cp = p++;
      for (j=0; *name && (*name != '.'); name++, j++)
	*p++ = *name;
      *cp = j;
      if (*name)
	name++;
    }
  *p++ = 0;
  j = p - sav - 2;
  PUTSHORT(j, sav); /* Real RDLENGTH */
  
  return p;
}

static int do_reverse_lookup(char *name, unsigned int nameoffset, char *limit, unsigned char **anspp)
{
  unsigned char *p = *anspp;
  struct crec *crecp = NULL;
  time_t now = time(NULL);
  struct in_addr addr = in_arpa_name_2_addr(name);
  int ans = 0;

  while ((crecp = cache_find_by_addr(crecp, addr, now)))
    { 
      p = add_text_record(nameoffset, p, 
			  (crecp->flags & F_IMMORTAL) ? 0 : crecp->ttd - now,
			  0, T_PTR, crecp->name);
      ans++;
      
      /* if last answer exceeded packet size, give up*/
      if (((unsigned char *)limit - p) < 0)
	return -ans;
	      
      *anspp = p;
    }
	  
       
  /* if not found in cache, see if it's in the private range. 
     If so return name as dotted quad */
  if (ans == 0 && boguspriv && private_net(addr))
    {
      p = add_text_record(nameoffset, p, 0, 0, T_PTR, inet_ntoa(addr));
      
      ans++;

      /* if last answer exceeded packet size, give up*/
      if (((unsigned char *)limit - p) < 0)
	return -ans;

      *anspp = p;
    }
  
  return ans;
}

static int do_mx_lookup(char *name, unsigned int nameoffset, char *limit, unsigned char **anspp)
{
  unsigned char *p = *anspp;
  char hostname[MAXDNAME];
  
  if (!mxname)
    return 0;

  if (gethostname(hostname, MAXDNAME) != 0)
    return 0;

  /* we return an mx record for a name given on the command line */
  if (strcmp(name, mxname) != 0)
    return 0;
  
  p = add_text_record(nameoffset, p, 0, 1, T_MX, hostname);

  /* if last answer exceeded packet size, set truncated bit */
  if (((unsigned char *)limit - p) < 0)
    return -1;
  
  *anspp = p;
  return 1;
}

/* insert a new cache entry at the head of the list (youngest entry) */
static void cache_insert(struct crec *crecp)
{
  if (cache_head) /* check needed for init code */
    cache_head->prev = crecp;
  crecp->next = cache_head;
  crecp->prev = NULL;
  cache_head = crecp;
}

/* get a cache entry to re-cycle from the tail of the list (oldest entry) */
static struct crec *cache_get_free(void)
{
  struct crec *ret = cache_tail;

  cache_tail = cache_tail->prev;
  cache_tail->next = NULL;

  /* just push immortal entries back to the top and try again. */
  if (ret->flags & F_IMMORTAL)
    {
      cache_insert(ret);
      return cache_get_free();
    }
	
  /* The next bit ensures that if there is more than one entry
     for a name or address, they all get removed at once */

  if (ret->flags & F_FORWARD)
    cache_remove_old_name(ret->name, 0);
  else if (ret->flags & F_REVERSE)
    cache_remove_old_addr(ret->addr, 0);
  
  return ret;
}

/* remove an arbitrary cache entry for promotion */ 
static void cache_unlink (struct crec *crecp)
{
  if (crecp->prev)
    crecp->prev->next = crecp->next;
  else
    cache_head = crecp->next;

  if (crecp->next)
    crecp->next->prev = crecp->prev;
  else
    cache_tail = crecp->prev;
}

static void cache_free(struct crec *crecp)
{
  cache_unlink(crecp);
  crecp->flags = 0;
  cache_tail->next = crecp;
  crecp->prev = cache_tail;
  crecp->next = NULL;
  cache_tail = crecp;
}

static void cache_mark_all_old(void)
{
  struct crec *crecp;
  
  for (crecp = cache_head; crecp; crecp = crecp->next)
    crecp->flags &= ~F_NEW;
}

static void cache_remove_old_name(char *name, time_t now)
{
  struct crec *crecp = cache_head;
  while (crecp)
    {
      struct crec *tmp = crecp->next;
      if (crecp->flags & F_FORWARD) 
	{
	  if (strcmp(crecp->name, name) == 0 && 
	      !(crecp->flags & (F_IMMORTAL | F_NEW)))
	    cache_free(crecp);
	  
	  if ((crecp->ttd < now) && !(crecp->flags & F_IMMORTAL))
	    cache_free(crecp);
	}
      crecp = tmp;
    }
  
}

static void cache_remove_old_addr(struct in_addr addr, time_t now)
{
  struct crec *crecp = cache_head;
  while (crecp)
    {
      struct crec *tmp = crecp->next;
      if (crecp->flags & F_REVERSE)
	{
	  
	  if (crecp->addr.s_addr == addr.s_addr && 
	      !(crecp->flags & (F_IMMORTAL | F_NEW)))
	    cache_free(crecp);
	  
	  /* remove expired entries too. */
	  if ((crecp->ttd < now) && !(crecp->flags & F_IMMORTAL))
	    cache_free(crecp);
	}
      crecp = tmp;
    }
  
}

static void cache_host_insert(struct crec *crecp, char *name, struct in_addr addr)
{
  crecp->flags = F_IMMORTAL | F_FORWARD | F_REVERSE;
  strcpy(crecp->name, name);
  crecp->addr = addr;
  cache_insert(crecp);
}

static void cache_name_insert(char *name, struct in_addr addr, time_t ttd)
{
  struct crec *crecp = cache_get_free();
  crecp->flags = F_NEW | F_FORWARD;
  strcpy(crecp->name, name);
  crecp->addr = addr;
  crecp->ttd = ttd;
  cache_insert(crecp);
}

static void cache_addr_insert(char *name, struct in_addr addr, time_t ttd)
{
  struct crec *crecp = cache_get_free();
  crecp->flags = F_NEW | F_REVERSE;
  strcpy(crecp->name, name);
  crecp->addr = addr;
  crecp->ttd = ttd;
  cache_insert(crecp);
}

static struct crec *cache_find_by_name(struct crec *crecp, char *name, time_t now)
{
  if (crecp) /* iterating */
    {
      if (crecp->next && 
	  (crecp->next->flags & F_FORWARD) && 
	  strcmp(crecp->next->name, name) == 0)
	return crecp->next;
      else
	return NULL;
    }
  
  /* first search, look for relevant entries and push to top of list
     also free anything which has expired */
  
  crecp = cache_head;
  while (crecp)
    {
      struct crec *tmp = crecp->next;
      if ((crecp->flags & F_FORWARD) && 
	  (strcmp(crecp->name, name) == 0))
	{
	  if ((crecp->flags & F_IMMORTAL) || crecp->ttd > now)
	    {
	      cache_unlink(crecp);
	      cache_insert(crecp);
	    }
	  else
	    cache_free(crecp);
	}
      crecp = tmp;
    }

  /* if there's anything relevant, it will be at the head of the cache now. */

  if (cache_head && (cache_head->flags & F_FORWARD) &&
      (strcmp(cache_head->name, name) == 0))
    return cache_head;

  return NULL;
}

static struct crec *cache_find_by_addr(struct crec *crecp, struct in_addr addr, time_t now)
{
  if (crecp) /* iterating */
    {
      if (crecp->next && (crecp->next->flags & F_REVERSE) && crecp->next->addr.s_addr == addr.s_addr)
	return crecp->next;
      else
	return NULL;
    }
  
  /* first search, look for relevant entries and push to top of list
     also free anything which has expired */
  
  crecp = cache_head;
  while (crecp)
    {
      struct crec *tmp = crecp->next;
      if ((crecp->flags & F_REVERSE) && 
	  crecp->addr.s_addr == addr.s_addr)
	{	    
	  if ((crecp->flags & F_IMMORTAL) || crecp->ttd > now)
	    {
	      cache_unlink(crecp);
	      cache_insert(crecp);
	    }
	  else
	      cache_free(crecp);
	}
      crecp = tmp;
    }

  /* if there's anything relevant, it will be at the head of the cache now. */

  if (cache_head && (cache_head->flags & F_REVERSE) &&
      cache_head->addr.s_addr == addr.s_addr)
    return cache_head;
  
  return NULL;
}

	    




