#include "server.h"

int main (int argc, char *argv[])
{
    char errorBuffer[PCAP_ERRBUF_SIZE];
    libnet_ptag_t ptag;
    libnet_t *myPacket;
    bpf_u_int32 net;
    bpf_u_int32 mask;
    pcap_if_t *nics;
    pcap_if_t *nic;
    
    /* Get the devices on the machine */
    if (pcap_findalldevs(&nics, errorBuffer) == -1)
    {
        systemFatal("Unable to retrieve device list");
    }
    
    for (nic = nics; nic; nic = nic->next) {
        if (pcap_lookupnet(nic->name, &net, &mask, errorBuffer) != -1)
        {
            break;
        }
    }
    
    /* Create the libnet context */
    myPacket = libnet_init(LIBNET_RAW4, nic->name, errorBuffer);
    if (myPacket == NULL)
    {
        systemFatal("Unable to set up libnet context");
    }

    /* Make the new UDP header */
    ptag = libnet_build_udp(
                            htons(69),    /* source port */
                            htons(69),    /* destination port */
                            LIBNET_UDP_H, /* packet size */
                            0,            /* checksum */
                            NULL,         /* payload */
                            0,            /* payload size */
                            myPacket,     /* libnet handle */
                            0);           /* libnet id */
    
    /* Error check */
    if (ptag == -1)
    {
        systemFatal("Error making UDP packet");
    }
    
    ptag = libnet_autobuild_ipv4(LIBNET_IPV4_H + LIBNET_UDP_H, IPPROTO_UDP, host_convert("192.168.0.89"), myPacket);
    
    
    /* Error check */
    if (ptag == -1)
    {
        systemFatal("Error making IP packet");
    }

    /* Send the packet out */
    if (libnet_write(myPacket) == -1)
    {
        systemFatal("Error sending packet");
    }
    libnet_clear_packet(myPacket);

    
    libnet_destroy(myPacket);
    return 0;

}