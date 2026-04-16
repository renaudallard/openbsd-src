/*
 * Fuzz harness for SSH banner and key exchange parsing.
 * Parses the initial SSH protocol exchange: version string,
 * kexinit packet structure, and algorithm lists.
 *
 * Does NOT do actual crypto - just validates structure.
 */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define SSH_MAX_BANNER	256
#define SSH_MAX_PACKET	(256 * 1024)
#define NAMELIST_MAX	1024

static int
parse_banner(const char *buf, size_t len, size_t *consumed)
{
	const char *p, *end, *nl;

	end = buf + len;
	p = buf;

	/* SSH banner: "SSH-2.0-xxxxx\r\n" */
	nl = memchr(p, '\n', end - p);
	if (nl == NULL)
		return -1;
	if (nl - p > SSH_MAX_BANNER)
		return -1;
	if (nl - p < 8)
		return -1;
	if (memcmp(p, "SSH-", 4) != 0)
		return -1;

	*consumed = (nl - p) + 1;
	return 0;
}

static int
parse_namelist(const char *buf, size_t len)
{
	/* Comma-separated algorithm names */
	char list[NAMELIST_MAX];
	char *p, *tok;
	int n = 0;

	if (len >= sizeof(list))
		return -1;
	memcpy(list, buf, len);
	list[len] = '\0';

	p = list;
	while ((tok = strsep(&p, ",")) != NULL) {
		if (strlen(tok) == 0)
			return -1;
		if (strlen(tok) > 64)
			return -1;
		n++;
	}
	return n;
}

static int
parse_kexinit(const uint8_t *buf, size_t len)
{
	uint32_t pktlen, padlen;
	const uint8_t *p, *end;
	uint32_t nllen;
	int i;

	if (len < 6)
		return -1;

	/* packet_length (4) + padding_length (1) + type (1) */
	pktlen = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
	    ((uint32_t)buf[2] << 8) | buf[3];
	padlen = buf[4];

	if (pktlen > SSH_MAX_PACKET || pktlen < 2)
		return -1;
	if (pktlen + 4 > len)
		return -1;

	/* Type byte */
	if (buf[5] != 20)	/* SSH_MSG_KEXINIT */
		return -1;

	/* 16 bytes cookie */
	p = buf + 6;
	end = buf + 4 + pktlen - padlen;
	if (p + 16 > end)
		return -1;
	p += 16;

	/* 10 name-lists: kex, hostkey, cipher c2s, cipher s2c,
	 * mac c2s, mac s2c, comp c2s, comp s2c, lang c2s, lang s2c */
	for (i = 0; i < 10; i++) {
		if (p + 4 > end)
			return -1;
		nllen = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
		    ((uint32_t)p[2] << 8) | p[3];
		p += 4;
		if (nllen > NAMELIST_MAX || p + nllen > end)
			return -1;
		parse_namelist((const char *)p, nllen);
		p += nllen;
	}

	/* first_kex_packet_follows (1 byte) */
	if (p + 1 > end)
		return -1;

	return 0;
}

int
main(int argc, char *argv[])
{
	FILE *fp;
	uint8_t buf[SSH_MAX_PACKET + 256];
	size_t len, consumed;

	if (argc < 2)
		fp = stdin;
	else {
		fp = fopen(argv[1], "rb");
		if (fp == NULL)
			return 1;
	}

	len = fread(buf, 1, sizeof(buf), fp);
	if (fp != stdin)
		fclose(fp);

	if (len == 0)
		return 1;

	/* Parse banner */
	consumed = 0;
	if (parse_banner((const char *)buf, len, &consumed) == 0) {
		/* Parse kexinit after banner */
		if (consumed < len)
			parse_kexinit(buf + consumed, len - consumed);
	} else {
		/* Try as raw kexinit packet */
		parse_kexinit(buf, len);
	}

	return 0;
}
