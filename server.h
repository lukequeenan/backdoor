#ifndef SERVER_H
#define SERVER_H

#define _BSD_SOURCE

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <pcap.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>

#include "sharedLibrary.h"

#define SNAP_LEN 1518

// Packet length
#define PCKT_LEN 8192

#define FILTER_BUFFER 1024
#define DEFAULT_DST_PORT	9000
#define DEFAULT_SRC_PORT	1234
#define DEFAULT_SRC_IP		"192.168.0.196"
#define OPTIONS 		"?h:d:s:p:c:"


struct AddrInfo
{
    char *DstHost;
    char *SrcHost;
    int dport;
    int sport;
};

unsigned short csum(unsigned short*, int);

char *encrypt_data(char *input, char *key)
{
    int i, x, y;
    
    x = strlen(input);
    y = strlen(key);
    
    for (i = 0; i < x; ++i)
    {
        input[i] ^= key[(i%y)];
    }
    return input;
}

int bind_address(int port, int *socket)
{
    struct sockaddr_in address;
    bzero((char *)&address, sizeof(struct sockaddr_in));
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    
    return bind(*socket, (struct sockaddr *)&address, sizeof(address));
}



#endif