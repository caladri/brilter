#include <err.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>

#include <pcap/pcap.h>

#include "cdefs.h"
#include "consumer.h"
#include "packet.h"
#include "pcap_filter.h"
#include "processor.h"

struct pcap_filter_processor {
	struct processor pfp_processor;
	struct bpf_program pfp_filter;
};

static bool pcap_filter_pass(struct pcap_filter_processor *, const uint8_t *, size_t);
static void pcap_filter_process(struct processor *, struct packet *, size_t, struct consumer *);

struct processor *
pcap_filter_processor(const char *filter)
{
	struct pcap_filter_processor *pfp;
	pcap_t *pcap;
	int rv;

	pfp = malloc(sizeof *pfp);
	if (pfp == NULL)
		errx(1, "malloc failed");

	pfp->pfp_processor.p_process = pcap_filter_process;

	pcap = pcap_open_dead(DLT_EN10MB /* XXX */, 2048 /* XXX */);
	if (pcap == NULL)
		errx(1, "pcap_open_dead failed");
	rv = pcap_compile(pcap, &pfp->pfp_filter, filter, 1, PCAP_NETMASK_UNKNOWN);
	if (rv == -1)
		errx(1, "pcap_compile: %s", pcap_geterr(pcap));
	pcap_close(pcap);

	return (&pfp->pfp_processor);
}

static bool
pcap_filter_pass(struct pcap_filter_processor *pfp, const uint8_t *data, size_t datalen)
{
	struct pcap_pkthdr hdr;
	int rv;

	/* NB: hdr.ts is not set because we don't care.  */
	hdr.caplen = datalen;
	hdr.len = datalen;

	/*
	 * Drop packets which don't match the filter.
	 */
	rv = pcap_offline_filter(&pfp->pfp_filter, &hdr, data);
	if (rv == 0)
		return (false);

	/*
	 * Pass packets which match the filter.
	 */
	return (true);
}

static void
pcap_filter_process(struct processor *processor, struct packet *pkts, size_t npkts, struct consumer *consumer)
{
	struct pcap_filter_processor *pfp;
	size_t cnpkts, n;

	pfp = container_of(processor, struct pcap_filter_processor, pfp_processor);

	cnpkts = 0;
	for (n = 0; n < npkts; n++) {
		if (!pcap_filter_pass(pfp, pkts[n].p_data, pkts[n].p_datalen))
			continue;
		pkts[cnpkts++] = pkts[n];
	}

	if (cnpkts != 0)
		consumer->c_consume(consumer, pkts, cnpkts);
}
