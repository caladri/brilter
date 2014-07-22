#include <assert.h>
#include <err.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <net/ethernet.h>
#include <netinet/in.h>

#include "consumer.h"
#include "netmap.h"
#include "packet.h"
#include "pipe.h"
#include "processor.h"

static bool brilter_pass(const uint8_t *, size_t);
static void brilter_process(struct processor *, struct packet *, size_t, struct consumer *);

static struct processor brilter_processor = {
	.p_process = brilter_process,
};

static void usage(void);

int
main(int argc, char *argv[])
{
	struct consumer *consumers[2];
	struct producer *producers[2];
	struct pipe *pipes[2];
	int ch;

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		case '?':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 2)
		usage();

	printf("Open consumers: %s", argv[0]);
	consumers[0] = netmap_consumer(argv[0]);
	printf(" %s\n", argv[1]);
	consumers[1] = netmap_consumer(argv[1]);

	if (consumers[0] == NULL || consumers[1] == NULL)
		errx(1, "unable to open consumers");

	printf("Open producers: %s", argv[0]);
	producers[0] = netmap_producer(argv[0]);
	printf(" %s\n", argv[1]);
	producers[1] = netmap_producer(argv[1]);

	if (producers[0] == NULL || producers[1] == NULL)
		errx(1, "unable to open producers");

	printf("Start pipe: %s->%s\n", argv[0], argv[1]);
	pipes[0] = pipe_start(producers[0], &brilter_processor, consumers[1]);
	printf("Start pipe: %s->%s\n", argv[1], argv[0]);
	pipes[1] = pipe_start(producers[1], &brilter_processor, consumers[0]);

	printf("Pipes started.\n");

	pipe_wait(pipes[0]);
	pipe_wait(pipes[1]);

	printf("Pipes finished.\n");

	return (0);
}

static bool
brilter_pass(const uint8_t *data, size_t datalen)
{
	struct ether_header eh;

	if (datalen < sizeof eh)
		return (false);

	memcpy(&eh, data, sizeof eh);
	data += sizeof eh;
	datalen -= sizeof eh;

	/*
	 * XXX
	 * Too-simple a start; only pass IPv6, but all IPv6.
	 */
	return (ntohs(eh.ether_type) == ETHERTYPE_IPV6);
}

static void
brilter_process(struct processor *processor, struct packet *pkts, size_t npkts, struct consumer *consumer)
{
	struct packet cpkts[npkts];
	size_t cnpkts;

	assert(processor == &brilter_processor);

	cnpkts = 0;
	while (npkts-- != 0) {
		if (brilter_pass(pkts[0].p_data, pkts[0].p_datalen))
			cpkts[cnpkts++] = pkts[0];
		pkts++;
	}

	if (cnpkts != 0)
		consumer->c_consume(consumer, cpkts, cnpkts);
}

static void
usage(void)
{
	fprintf(stderr, "usage: brilter if0 if1\n");
	exit(1);
}
