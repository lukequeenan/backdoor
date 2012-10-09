#include "server.h"

int main (int argc, char *argv[])
{
    char errorBuffer[PCAP_ERRBUF_SIZE];
    char *command;
    bpf_u_int32 net;
    bpf_u_int32 mask;
    pcap_if_t *nics;
    pcap_if_t *nic;
    struct AddrInfo *addr;
    int opt;
    time_t t;
    struct tm* tm;
    char Date[11];
    char *encryptedField;
    unsigned int count;
    int sd;
    // No data, just datagram
    char buffer[PCKT_LEN];
    // The size of the headers
    struct ip *iph = (struct ip *) buffer;
    struct tcphdr *tcph = (struct tcphdr *) (buffer + sizeof(struct ip));
    struct sockaddr_in sin, din;
    int one = 1;
    const int *val = &one;

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
    //command = strdup("/dev/bin");
    
    strftime(Date, sizeof Date, "%Y:%m:%d", tm);
    printf("%s\n", Date);
    
    encryptedField = encrypt_data(command, Date);
    printf("%s\n", encryptedField);
    
    encryptedField = encrypt_data(encryptedField, Date);
    printf("%s\n", encryptedField);

    
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
    
    // The source is redundant, may be used later if needed
    // Address family
    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;
    // Source port, can be any, modify as needed
    sin.sin_port = htons(addr->sport);
    din.sin_port = htons(addr->dport);
    // Source IP, can be any, modify as needed
    sin.sin_addr.s_addr = inet_addr((addr->SrcHost));
    din.sin_addr.s_addr = inet_addr((addr->DstHost));
    // IP structure
    iph->ip_hl = 20;
    iph->ip_v = 4;
    iph->ip_tos = 16;
    iph->ip_len = sizeof(struct ip) + sizeof(struct tcphdr);
    iph->ip_id = htons(54321);
    iph->ip_off = 0;
    iph->ip_ttl = 64;
    iph->ip_p = 6;	// TCP
    iph->ip_sum = 0;		// Done by kernel
    
    // Source IP, modify as needed, spoofed, we accept through command line argument
    iph->ip_src = sin.sin_addr;
    // Destination IP, modify as needed, but here we accept through command line argument
    iph->ip_dst = din.sin_addr;
    
    // The TCP structure. The source port, spoofed, we accept through the command line
    tcph->th_sport = htons(addr->sport);
    // The destination port, we accept through command line
    tcph->th_dport = htons(addr->dport);
    tcph->th_seq = htonl(1);
    tcph->th_ack = 0;
    tcph->th_off = 5;
    tcph->th_flags = TH_SYN;
    tcph->th_win = htons(32767);
    tcph->th_sum = 0;	// Done by kernel
    tcph->th_urp = 0;
    
    // IP checksum calculation
    iph->ip_sum = csum((unsigned short *) buffer, (sizeof(struct ip) + sizeof(struct tcphdr)));
    
    // Inform the kernel do not fill up the headers' structure, we fabricated our own
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("setsockopt() error");
        exit(-1);
    } else {
        printf("setsockopt() is OK\n");
    }
    printf("Using:::::Source IP: %s port: %d, Target IP: %s port: %d.\n", (addr->SrcHost), addr->sport, (addr->DstHost), addr->dport);
    
    // sendto() loop, send every 2 second for 50 counts
    
    for (count = 0; count < 2; count++) {
        if (sendto(sd, buffer, iph->ip_len, 0, (struct sockaddr *) &sin, sizeof(sin)) < 0)
            // Verify
        {
            perror("sendto() error");
            exit(-1);
        } else
            printf("Count #%u - sendto() is OK\n", count);
        //sleep(2);
    }
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