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

#include <pcap/pcap.h>

#include "cdefs.h"
#include "consumer.h"
#include "netmap.h"
#include "packet.h"
#include "pipe.h"
#include "processor.h"

struct brilter_state {
	struct processor bs_processor;
	struct bpf_program bs_filter;
};

static bool brilter_pass(struct brilter_state *, const uint8_t *, size_t);
static void brilter_process(struct processor *, struct packet *, size_t, struct consumer *);
static struct processor *brilter_processor(const char *);

static void usage(void);

#define	IP6_LINK_LOCAL_TRAFFIC_P	"(ip6 src net fe80::/112 and ip6 dst net fe80::/112)"
#define	IP6_MULTICAST_P			"(ip6 multicast)"
#define	ICMP6_P				"(icmp6)"
#define	IP6_TCP_P			"(ip6 proto \\tcp)"
#define	TCP_DST_PORT_P(port)		"(tcp dst port " port ")"
#define	TCP_SYN_P			"(tcp[tcpflags] & (tcp-syn | tcp-ack) == tcp-syn)"

/*
 * Allow link-local traffic, multicast and icmp6 in both directions.
 */
#define	BASE_FILTER	"(" IP6_LINK_LOCAL_TRAFFIC_P "||" IP6_MULTICAST_P "||" ICMP6_P ")"
/*
 * Allow inbound traffic TCP traffic that isn't a SYN unless the destination port is 22.
 */
#define	INBOUND_FILTER	"(" BASE_FILTER "||" "(" IP6_TCP_P "&&" "(" "(" "!" TCP_SYN_P ")" "||" "(" TCP_DST_PORT_P("22") ")" ")" ")" ")"
/*
 * Allow outbound traffic that is TCP, or that meets the base criteria.
 */
#define	OUTBOUND_FILTER	"(" BASE_FILTER "||" IP6_TCP_P ")"

int
main(int argc, char *argv[])
{
	const char *inbound_filter, *outbound_filter;
	struct processor *processors[2];
	struct consumer *consumers[2];
	struct producer *producers[2];
	struct pipe *pipes[2];
	const char *lan, *wan;
	bool daemonize;
	int ch;
	int rv;

	inbound_filter = INBOUND_FILTER;
	outbound_filter = OUTBOUND_FILTER;
	daemonize = false;

	while ((ch = getopt(argc, argv, "I:O:d")) != -1) {
		switch (ch) {
		case 'I':
			inbound_filter = optarg;
			break;
		case 'O':
			outbound_filter = optarg;
			break;
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

	processors[0] = brilter_processor(outbound_filter);
	processors[1] = brilter_processor(inbound_filter);

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
	struct pcap_pkthdr hdr;
	int rv;

	/* NB: hdr.ts is not set because we don't care.  */
	hdr.caplen = datalen;
	hdr.len = datalen;

	/*
	 * Drop packets which don't match the filter.
	 */
	rv = pcap_offline_filter(&bs->bs_filter, &hdr, data);
	if (rv == 0)
		return (false);

	/*
	 * Pass packets which match the filter.
	 */
	return (true);
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
brilter_processor(const char *filter)
{
	struct brilter_state *bs;
	pcap_t *pcap;
	int rv;

	bs = malloc(sizeof *bs);
	if (bs == NULL)
		errx(1, "malloc failed");

	bs->bs_processor.p_process = brilter_process;

	pcap = pcap_open_dead(DLT_EN10MB /* XXX */, 2048 /* XXX */);
	if (pcap == NULL)
		errx(1, "pcap_open_dead failed");
	rv = pcap_compile(pcap, &bs->bs_filter, filter, 1, PCAP_NETMASK_UNKNOWN);
	if (rv == -1)
		errx(1, "pcap_compile: %s", pcap_geterr(pcap));
	pcap_close(pcap);

	return (&bs->bs_processor);
}

static void
usage(void)
{
	fprintf(stderr, "usage: brilter [-I inbound-filter] [-O outbound-filter] [-d] lan-interface wan-interface\n");
	exit(1);
}
