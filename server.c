#include "server.h"

int main (int argc, char *argv[])
{
    char errorBuffer[PCAP_ERRBUF_SIZE];
    char *command;
    libnet_ptag_t ptag;
    libnet_t *myPacket;
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

    time(&t);
    tm = localtime(&t);
    
    addr = malloc(sizeof(struct AddrInfo));
    
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
    command = strdup("/dev/bin");
    
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
    
    /* Create the libnet context */
    myPacket = libnet_init(LIBNET_RAW4, nic->name, errorBuffer);
    if (myPacket == NULL)
    {
        systemFatal("Unable to set up libnet context");
    }

    /* Make the new UDP header */
    ptag = libnet_build_udp(
                            htons(addr->sport),    /* source port */
                            htons(addr->dport),    /* destination port */
                            32,           /* packet size */
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
    
    /* Encrypt our command with the date */
    
    //encryptedField = Date / errorBuffer;

    /* Make the IP header */
    ptag = libnet_build_ipv4(
                             5,                                          /* length */
                             0,                                          /* TOS */
                             (int)(255.0 * rand() / RAND_MAX + 1.0),     /* IP ID */
                             0,                                          /* IP Frag */
                             64,                                         /* TTL */
                             IPPROTO_UDP,                                /* protocol */
                             0,                                          /* checksum */
                             *(addr->SrcHost),                                   /* source IP */
                             *(addr->DstHost),                              /* destination IP */
                             NULL,                                       /* payload */
                             0,                                          /* payload size */
                             myPacket,                                   /* libnet handle */
                             0);                                         /* libnet id */
    
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
    
    /* Clean up */
    libnet_clear_packet(myPacket);
    libnet_destroy(myPacket);
    
    return 0;
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