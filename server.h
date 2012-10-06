#ifndef SERVER_H
#define SERVER_H

#include <libnet.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <pcap.h>
#include <unistd.h>

#include "sharedLibrary.h"

#define SNAP_LEN 1518

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

#endif