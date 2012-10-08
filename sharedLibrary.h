#ifndef SHARED_LIBRARY_H
#define SHARED_LIBRARY_H

//#define __USE_BSD
//#define __FAVOR_BSD

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SIZE_ETHERNET 14

unsigned int host_convert (char *hostname);
void systemFatal(const char *message);

#endif
