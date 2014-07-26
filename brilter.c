#include <assert.h>
#include <err.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>

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

	if (argc != 2)
		usage();

	if (daemonize) {
		rv = daemon(0, 0);
		if (rv == -1)
			err(1, "daemon");
	}

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
	struct ip6_hdr ip6;

	if (datalen < sizeof eh)
		return (false);

	memcpy(&eh, data, sizeof eh);
	data += sizeof eh;
	datalen -= sizeof eh;

	/*
	 * We're only interested in passing IPv6 traffic.
	 */
	if (ntohs(eh.ether_type) != ETHERTYPE_IPV6)
		return (false);

	if (datalen < sizeof ip6)
		return (false);

	memcpy(&ip6, data, sizeof ip6);
	data += sizeof ip6;
	datalen -= sizeof ip6;

	if ((ip6.ip6_vfc & IPV6_VERSION_MASK) != IPV6_VERSION)
		return (false);

	/*
	 * Only interested in allowing ICMP6 and maybe TCP6.
	 * XXX
	 * What about UDP?
	 */
	switch (ip6.ip6_nxt) {
	case IPPROTO_ICMPV6:
		return (true);
	case IPPROTO_TCP:
		break;
	default:
		return (false);
	}

	/*
	 * Pass any link-local to link-local traffic, i.e. fe80::/112
	 * to fe80::/112.
	 */
	if (ip6.ip6_src.s6_addr[0] == 0xfe && ip6.ip6_src.s6_addr[1] == 0x80 &&
	    ip6.ip6_dst.s6_addr[0] == 0xfe && ip6.ip6_dst.s6_addr[1] == 0x80)
		return (true);

	/*
	 * And anything destined for link-local multicast, i.e. fe?2::/112.
	 */
	if (ip6.ip6_dst.s6_addr[0] == 0xfe && (ip6.ip6_dst.s6_addr[1] & 0x0f) == 0x02)
		return (true);

	/*
	 * TODO
	 * Block inbound TCP SYNs except to port 22.
	 */

	/*
	 * Pass all remaining TCP traffic.
	 */
	return (true);
}

static void
brilter_process(struct processor *processor, struct packet *pkts, size_t npkts, struct consumer *consumer)
{
	struct packet cpkts[npkts];
	size_t cnpkts;

	(void)processor;

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
	fprintf(stderr, "usage: brilter [-d] if0 if1\n");
	exit(1);
}
