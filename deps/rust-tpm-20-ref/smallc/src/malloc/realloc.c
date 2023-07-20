#include <stdlib.h>

extern void *__fw_realloc(void *p, size_t n);

void *realloc(void *p, size_t n)
{
	return __fw_realloc(p, n);
}
