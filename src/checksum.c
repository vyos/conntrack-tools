/* 
 * Extracted from RFC 1071 with some minor changes to fix compilation on GCC,
 * this can probably be improved
 * 					--pablo 11/feb/07
 */

#include <conntrackd.h>

unsigned short do_csum(const void *addr, unsigned int count)
{
	unsigned int sum = 0;

	/* checksumming disabled, just skip */
	if (CONFIG(flags) & DONT_CHECKSUM)
		return 0;

	while(count > 1)  {
		/*  This is the inner loop */
		sum += *((unsigned short *) addr++);
		count -= 2;
	}

	/*  Add left-over byte, if any */
	if(count > 0)
		sum += *((unsigned char *) addr);

	/*  Fold 32-bit sum to 16 bits */
	while (sum>>16)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}
