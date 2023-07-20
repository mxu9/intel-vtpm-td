#include <err.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

extern char *__progname;

int errno = 0;

void vwarn(const char *fmt, va_list ap)
{
	printf ("%s: ", __progname);
	if (fmt) {
		printf(fmt, ap);
	}
}

void vwarnx(const char *fmt, va_list ap)
{
	printf ("%s: ", __progname);
	if (fmt) printf(fmt, ap);
}

_Noreturn void verr(int status, const char *fmt, va_list ap)
{
	vwarn(fmt, ap);
}

_Noreturn void verrx(int status, const char *fmt, va_list ap)
{
	vwarnx(fmt, ap);
}

void warn(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vwarn(fmt, ap);
	va_end(ap);
}

void warnx(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vwarnx(fmt, ap);
	va_end(ap);
}

_Noreturn void err(int status, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	verr(status, fmt, ap);
	va_end(ap);
}

_Noreturn void errx(int status, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	verrx(status, fmt, ap);
	va_end(ap);
}
