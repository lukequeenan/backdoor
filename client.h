#ifndef CLIENT_H
#define CLIENT_H

#define _BSD_SOURCE

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <pcap.h>
#include <unistd.h>

#include "sharedLibrary.h"

#define SNAP_LEN 1518
#define FILTER_BUFFER 1024
#define SOURCE_IP "192.168.0.79"
#define SOURCE_PORT "1234"

#define MASK "/usr/sbin/apache2 -k start -DSSL"

int client();
void receivedPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

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

#endif