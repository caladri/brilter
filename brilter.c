#include <assert.h>
#include <err.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

#include "cdefs.h"
#include "consumer.h"
#include "netmap.h"
#include "packet.h"
#include "pipe.h"
#include "processor.h"

enum brilter_direction {
	brilter_inbound,
	brilter_outbound,
};

struct brilter_state {
	struct processor bs_processor;
	enum brilter_direction bs_direction;
};

static bool brilter_pass(struct brilter_state *, const uint8_t *, size_t);
static void brilter_process(struct processor *, struct packet *, size_t, struct consumer *);
static struct processor *brilter_processor(enum brilter_direction);

static void usage(void);

int
main(int argc, char *argv[])
{
	struct processor *processors[2];
	struct consumer *consumers[2];
	struct producer *producers[2];
	struct pipe *pipes[2];
	const char *lan, *wan;
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

	lan = argv[0];
	wan = argv[1];

	printf("Open consumers: %s(LAN)", lan);
	consumers[0] = netmap_consumer(lan);
	printf(" %s(WAN)\n", wan);
	consumers[1] = netmap_consumer(wan);

	if (consumers[0] == NULL || consumers[1] == NULL)
		errx(1, "unable to open consumers");

	printf("Open producers: %s(LAN)", lan);
	producers[0] = netmap_producer(lan);
	printf(" %s(WAN)\n", wan);
	producers[1] = netmap_producer(wan);

	if (producers[0] == NULL || producers[1] == NULL)
		errx(1, "unable to open producers");

	processors[0] = brilter_processor(brilter_outbound);
	processors[1] = brilter_processor(brilter_inbound);

	printf("Start outbound pipe: %s(LAN)->%s(WAN)\n", lan, wan);
	pipes[0] = pipe_start(producers[0], processors[0], consumers[1]);
	printf("Start inbound pipe: %s(WAN)->%s(LAN)\n", wan, lan);
	pipes[1] = pipe_start(producers[1], processors[1], consumers[0]);

	printf("Pipes started.\n");

	pipe_wait(pipes[0]);
	pipe_wait(pipes[1]);

	printf("Pipes finished.\n");

	return (0);
}

static bool
brilter_pass(struct brilter_state *bs, const uint8_t *data, size_t datalen)
{
	struct ether_header eh;
	struct ip6_hdr ip6;
	struct tcphdr th;

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
	 * Only interested in allowing ICMP6 and maybe TCP6 with the outside world.
	 * XXX
	 * What about non-local UDP?
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
	 * Allow all outbound TCP traffic.
	 *
	 * Note: we can decide this without looking at the TCP header.
	 */
	if (bs->bs_direction == brilter_outbound)
		return (true);

	/*
	 * Allow anything inbound that isn't a SYN.
	 */
	if (datalen < sizeof th)
		return (false);

	memcpy(&th, data, sizeof th);
	data += sizeof th;
	datalen -= sizeof th;

	if ((th.th_flags & (TH_SYN | TH_ACK)) != TH_SYN)
		return (true);

	/*
	 * Allow inbound SYNs to port 22.
	 */
	if (ntohs(th.th_dport) == 22)
		return (true);

	/*
	 * Deny all other inbound SYNs.
	 */
	return (false);
}

static void
brilter_process(struct processor *processor, struct packet *pkts, size_t npkts, struct consumer *consumer)
{
	struct packet cpkts[npkts];
	struct brilter_state *bs;
	size_t cnpkts;

	bs = container_of(processor, struct brilter_state, bs_processor);

	cnpkts = 0;
	while (npkts-- != 0) {
		if (brilter_pass(bs, pkts[0].p_data, pkts[0].p_datalen))
			cpkts[cnpkts++] = pkts[0];
		pkts++;
	}

	if (cnpkts != 0)
		consumer->c_consume(consumer, cpkts, cnpkts);
}

static struct processor *
brilter_processor(enum brilter_direction direction)
{
	struct brilter_state *bs;

	bs = malloc(sizeof *bs);
	if (bs == NULL)
		errx(1, "malloc failed");

	bs->bs_processor.p_process = brilter_process;
	bs->bs_direction = direction;

	return (&bs->bs_processor);
}

static void
usage(void)
{
	fprintf(stderr, "usage: brilter [-d] lan-interface wan-interface\n");
	exit(1);
}
