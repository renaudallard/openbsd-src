# Build standalone fuzz harnesses.
#
# build.sh invokes "make CC=afl-clang-fast COPTS=... LDFLAGS=..." and then
# looks for a binary named after the target (httpd_fuzz / smtpd_fuzz /
# sshd_fuzz) in this directory.

CC?=		cc
COPTS?=
CFLAGS?=
LDFLAGS?=

HARNESSES=	httpd_fuzz smtpd_fuzz sshd_fuzz

all: ${HARNESSES}

httpd_fuzz: httpd_request_fuzz.c
	${CC} ${COPTS} ${CFLAGS} ${LDFLAGS} -o $@ httpd_request_fuzz.c

smtpd_fuzz: smtpd_parse_fuzz.c
	${CC} ${COPTS} ${CFLAGS} ${LDFLAGS} -o $@ smtpd_parse_fuzz.c

sshd_fuzz: sshd_auth_fuzz.c
	${CC} ${COPTS} ${CFLAGS} ${LDFLAGS} -o $@ sshd_auth_fuzz.c

clean:
	rm -f ${HARNESSES}

.PHONY: all clean
