/*
 * Fuzz harness for smtpd SMTP command parsing.
 * Feeds AFL input as SMTP commands line by line.
 */

#include <sys/types.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXLINESIZE	2048
#define MAXARGS		64

struct smtp_cmd {
	const char *verb;
	int code;
};

static const struct smtp_cmd cmds[] = {
	{ "HELO", 250 },
	{ "EHLO", 250 },
	{ "MAIL", 250 },
	{ "RCPT", 250 },
	{ "DATA", 354 },
	{ "RSET", 250 },
	{ "NOOP", 250 },
	{ "QUIT", 221 },
	{ "VRFY", 252 },
	{ "EXPN", 502 },
	{ "HELP", 214 },
	{ "STARTTLS", 220 },
	{ "AUTH", 334 },
	{ NULL, 0 }
};

static int
parse_address(const char *arg, char *addr, size_t addrlen)
{
	const char *p, *start, *end;

	/* Find <addr> or bare addr */
	p = strchr(arg, '<');
	if (p != NULL) {
		start = p + 1;
		end = strchr(start, '>');
		if (end == NULL)
			return -1;
	} else {
		start = arg;
		while (*start == ' ')
			start++;
		end = start;
		while (*end && *end != ' ')
			end++;
	}

	if ((size_t)(end - start) >= addrlen)
		return -1;

	memcpy(addr, start, end - start);
	addr[end - start] = '\0';

	return 0;
}

static int
parse_params(const char *line, char **params, int maxparams)
{
	char *copy, *p, *tok;
	int n = 0;

	copy = strdup(line);
	if (copy == NULL)
		return -1;

	p = copy;
	while (n < maxparams && (tok = strsep(&p, " \t")) != NULL) {
		if (*tok == '\0')
			continue;
		params[n] = strdup(tok);
		if (params[n] == NULL)
			break;
		n++;
	}
	free(copy);
	return n;
}

static int
process_line(const char *line, size_t len)
{
	char verb[16], addr[256];
	char *params[MAXARGS];
	const char *arg;
	int i, nparams;

	if (len == 0)
		return 0;

	/* Extract verb */
	for (i = 0; i < (int)sizeof(verb) - 1 && i < (int)len; i++) {
		if (line[i] == ' ' || line[i] == '\r' || line[i] == '\n')
			break;
		verb[i] = toupper((unsigned char)line[i]);
	}
	verb[i] = '\0';

	/* Match command */
	for (i = 0; cmds[i].verb != NULL; i++) {
		if (strcmp(verb, cmds[i].verb) == 0)
			break;
	}

	/* Parse arguments based on command */
	arg = line + strlen(verb);
	while (*arg == ' ')
		arg++;

	if (strcmp(verb, "MAIL") == 0 || strcmp(verb, "RCPT") == 0) {
		/* Parse FROM:/TO: <addr> PARAM=VALUE ... */
		if (strncasecmp(arg, "FROM:", 5) == 0)
			arg += 5;
		else if (strncasecmp(arg, "TO:", 3) == 0)
			arg += 3;
		parse_address(arg, addr, sizeof(addr));
	}

	nparams = parse_params(arg, params, MAXARGS);
	for (i = 0; i < nparams; i++)
		free(params[i]);

	return 0;
}

int
main(int argc, char *argv[])
{
	FILE *fp;
	char buf[65536];
	size_t len;
	char *p, *lp, *end;

	if (argc < 2)
		fp = stdin;
	else {
		fp = fopen(argv[1], "r");
		if (fp == NULL)
			return 1;
	}

	len = fread(buf, 1, sizeof(buf) - 1, fp);
	if (fp != stdin)
		fclose(fp);
	buf[len] = '\0';

	/* Process line by line like SMTP session */
	p = buf;
	end = buf + len;
	while (p < end) {
		lp = memchr(p, '\n', end - p);
		if (lp == NULL)
			lp = end;
		/* Strip \r\n */
		size_t llen = lp - p;
		if (llen > 0 && p[llen - 1] == '\r')
			llen--;
		process_line(p, llen);
		p = lp + 1;
	}

	return 0;
}
