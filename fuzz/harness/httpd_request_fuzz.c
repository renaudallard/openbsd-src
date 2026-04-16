/*
 * Fuzz harness for httpd HTTP request parsing.
 * Feeds AFL input directly to server_http_parseheaders().
 *
 * Build: cc -o httpd_fuzz httpd_request_fuzz.c -I../../usr.sbin/httpd
 *        (needs httpd object files linked in)
 *
 * Simpler approach: extract just the parser into a standalone.
 */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Minimal standalone HTTP request line + header parser.
 * Extracted from httpd server_http.c logic.
 * Doesn't need the full httpd machinery.
 */

#define MAXHDRLEN	8192
#define MAXHEADERS	64

struct header {
	char *key;
	char *val;
};

static int
parse_request(const char *buf, size_t len)
{
	char line[MAXHDRLEN];
	const char *p, *end, *lp;
	char *method, *path, *version, *sp;
	struct header hdrs[MAXHEADERS];
	int nhdr = 0;
	size_t llen;

	end = buf + len;
	p = buf;

	/* Find end of request line */
	lp = memchr(p, '\n', end - p);
	if (lp == NULL)
		return -1;
	llen = lp - p;
	if (llen >= sizeof(line))
		return -1;
	memcpy(line, p, llen);
	line[llen] = '\0';
	/* Strip \r */
	if (llen > 0 && line[llen - 1] == '\r')
		line[--llen] = '\0';

	/* Parse "METHOD PATH VERSION" */
	method = line;
	sp = strchr(method, ' ');
	if (sp == NULL)
		return -1;
	*sp++ = '\0';
	path = sp;
	sp = strchr(path, ' ');
	if (sp == NULL)
		return -1;
	*sp++ = '\0';
	version = sp;

	/* Validate method */
	if (strcmp(method, "GET") != 0 &&
	    strcmp(method, "POST") != 0 &&
	    strcmp(method, "HEAD") != 0 &&
	    strcmp(method, "PUT") != 0 &&
	    strcmp(method, "DELETE") != 0 &&
	    strcmp(method, "OPTIONS") != 0)
		return -1;

	/* Validate version */
	if (strncmp(version, "HTTP/", 5) != 0)
		return -1;

	p = lp + 1;

	/* Parse headers */
	while (p < end && nhdr < MAXHEADERS) {
		lp = memchr(p, '\n', end - p);
		if (lp == NULL)
			break;
		llen = lp - p;
		if (llen >= sizeof(line))
			return -1;
		memcpy(line, p, llen);
		line[llen] = '\0';
		if (llen > 0 && line[llen - 1] == '\r')
			line[--llen] = '\0';

		/* Empty line = end of headers */
		if (llen == 0)
			break;

		/* Split "Key: Value" */
		sp = strchr(line, ':');
		if (sp == NULL)
			return -1;
		*sp++ = '\0';
		while (*sp == ' ' || *sp == '\t')
			sp++;

		hdrs[nhdr].key = strdup(line);
		hdrs[nhdr].val = strdup(sp);
		nhdr++;

		p = lp + 1;
	}

	/* Cleanup */
	for (int i = 0; i < nhdr; i++) {
		free(hdrs[i].key);
		free(hdrs[i].val);
	}

	return 0;
}

int
main(int argc, char *argv[])
{
	FILE *fp;
	char buf[65536];
	size_t len;

	if (argc < 2) {
		fp = stdin;
	} else {
		fp = fopen(argv[1], "r");
		if (fp == NULL)
			return 1;
	}

	len = fread(buf, 1, sizeof(buf), fp);
	if (fp != stdin)
		fclose(fp);

	if (len == 0)
		return 1;

	parse_request(buf, len);
	return 0;
}
