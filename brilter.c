#include <sys/endian.h>
#include <assert.h>
#include <err.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
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
	const uint8_t *src, *dst;
	uint16_t dport, etype;
	uint8_t nxt, vfc, flags;

	/* Examine Ethernet header.  */
	if (datalen < sizeof (struct ether_header))
		return (false);

	/*
	 * We're only interested in passing IPv6 traffic.
	 */
	etype = be16dec(field_ptr(data, struct ether_header, ether_type));
	if (etype != ETHERTYPE_IPV6)
		return (false);

	/* Skip Ethernet header.  */
	data += sizeof (struct ether_header);
	datalen -= sizeof (struct ether_header);

	/* Examine IPv6 header.  */
	if (datalen < sizeof (struct ip6_hdr))
		return (false);

	/*
	 * Check for correct version.
	 */
	vfc = *(const uint8_t *)field_ptr(data, struct ip6_hdr, ip6_vfc);
	if ((vfc & IPV6_VERSION_MASK) != IPV6_VERSION)
		return (false);

	/*
	 * Pass any link-local to link-local traffic, i.e. fe80::/112
	 * to fe80::/112.
	 */
	src = field_ptr(data, struct ip6_hdr, ip6_src.s6_addr[0]);
	dst = field_ptr(data, struct ip6_hdr, ip6_dst.s6_addr[0]);
	if (src[0] == 0xfe && src[1] == 0x80 && dst[0] == 0xfe && dst[1] == 0x80)
		return (true);

	/*
	 * And anything destined for link-local multicast, i.e. fe?2::/112.
	 */
	if (dst[0] == 0xfe && (dst[1] & 0x0f) == 0x02)
		return (true);

	/*
	 * Only interested in allowing ICMP6 and maybe TCP6 with the outside world.
	 * XXX
	 * What about non-local UDP?
	 */
	nxt = *(const uint8_t *)field_ptr(data, struct ip6_hdr, ip6_nxt);
	switch (nxt) {
	case IPPROTO_ICMPV6:
		return (true);
	case IPPROTO_TCP:
		break;
	default:
		return (false);
	}

	/* Skip IPv6 header.  */
	data += sizeof (struct ip6_hdr);
	datalen -= sizeof (struct ip6_hdr);

	/*
	 * Allow all outbound TCP traffic.
	 *
	 * Note: we can decide this without looking at the TCP header.
	 */
	if (bs->bs_direction == brilter_outbound)
		return (true);

	/* Examine TCP header.  */
	if (datalen < sizeof (struct tcphdr))
		return (false);

	/*
	 * Allow anything inbound that isn't a SYN.
	 */
	flags = *(const uint8_t *)field_ptr(data, struct tcphdr, th_flags);
	if ((flags & (TH_SYN | TH_ACK)) != TH_SYN)
		return (true);

	/*
	 * Allow inbound SYNs to port 22.
	 */
	dport = be16dec(field_ptr(data, struct tcphdr, th_dport));
	if (dport == 22)
		return (true);

	/*
	 * Deny all other inbound SYNs.
	 */
	return (false);
}

static void
brilter_process(struct processor *processor, struct packet *pkts, size_t npkts, struct consumer *consumer)
{
	struct brilter_state *bs;
	size_t cnpkts, n;

	bs = container_of(processor, struct brilter_state, bs_processor);

	cnpkts = 0;
	for (n = 0; n < npkts; n++) {
		if (!brilter_pass(bs, pkts[n].p_data, pkts[n].p_datalen))
			continue;
		pkts[cnpkts++] = pkts[n];
	}

	if (cnpkts != 0)
		consumer->c_consume(consumer, pkts, cnpkts);
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
