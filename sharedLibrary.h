#ifndef SHARED_LIBRARY_H
#define SHARED_LIBRARY_H

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SIZE_ETHERNET 14
#define TRUE 1

unsigned int host_convert (char *hostname);
void systemFatal(const char *message);
int bind_address(int port, int *socket);
char *encrypt_data(char*, char*);

#endif