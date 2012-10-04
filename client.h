#ifndef CLIENT_H
#define CLIENT_H

#include <libnet.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <pcap.h>
#include <unistd.h>

#include "sharedLibrary.h"

#define SNAP_LEN 1518
#define FILTER_BUFFER 1024

#define MASK "/usr/sbin/apache2 -k start -DSSL"

int client();
void receivedPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif