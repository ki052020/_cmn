#include	<stdio.h>
#include "my_basic.h"

// ---------------------------------------------------------------
void DBG_dump(const void* const pbuf, const int bytes)
{
	enum { EN_bytes_limit = 16 * 4 };

	printf("--- DBG_dump\n");
	const uint8_t* pbyte = (const uint8_t*)pbuf;

	for (int i = 0 ; i < bytes; ) {
		if (i == EN_bytes_limit)
		{
			printf("snipped...");
			break;
		}

		printf("%02x ", *pbyte++);
		if (((++i) & 0xf) == 0) { printf("\n"); }
	}
	printf("\n\n");
}

