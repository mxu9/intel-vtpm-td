#include <stdlib.h>

extern void __fw_free(void *p);

void free(void *p)
{
	__fw_free(p);
}
