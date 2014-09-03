#include <err.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "script.h"

static void usage(void);

int
main(int argc, char *argv[])
{
	bool daemonize;
	int ch;
	int rv;

	daemonize = false;

	while ((ch = getopt(argc, argv, "d")) != -1) {
		switch (ch) {
		case 'd':
			daemonize = true;
			break;
		case '?':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();

	if (daemonize) {
		rv = daemon(0, 0);
		if (rv == -1)
			err(1, "daemon");
	}

	script_execute(argv[0]);

	return (0);
}

static void
usage(void)
{
	fprintf(stderr, "usage: brilter [-d] script-file\n");
	exit(1);
}
