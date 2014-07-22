#include <sys/types.h>
#include <sys/poll.h>
#include <sys/queue.h>
#include <assert.h>
#include <err.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define	NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#include "consumer.h"
#include "netmap.h"
#include "packet.h"
#include "processor.h"
#include "producer.h"

#define	NETMAP_PACKET_COUNT	(1024)

struct netmap_handle {
	struct nm_desc *nh_d;
	struct consumer nh_consumer;
	struct producer nh_producer;
	char nh_ifname[IFNAMSIZ];
	STAILQ_ENTRY(netmap_handle) nh_link;
	struct packet nh_packets[NETMAP_PACKET_COUNT];
};

static STAILQ_HEAD(, netmap_handle) netmap_handles =
	STAILQ_HEAD_INITIALIZER(netmap_handles);

static void consumer_netmap_consume(struct consumer *, struct packet *, size_t);
static void producer_netmap_produce(struct producer *, struct processor *, struct consumer *);

static struct netmap_handle *netmap_handle_open(const char *);

struct consumer *
netmap_consumer(const char *iface)
{
	struct netmap_handle *nh;

	nh = netmap_handle_open(iface);
	if (nh == NULL)
		return (NULL);
	return (&nh->nh_consumer);
}

static void
consumer_netmap_consume(struct consumer *consumer, struct packet *pkts, size_t npkts)
{
	struct netmap_handle *nh;
	struct netmap_ring *ring;
	struct netmap_slot *slot;
	int rv;

	nh = (struct netmap_handle *)((uintptr_t)consumer - offsetof(struct netmap_handle, nh_consumer));

	nh->nh_d->cur_tx_ring = nh->nh_d->first_tx_ring;

	while (npkts != 0) {
		ring = NETMAP_TXRING(nh->nh_d->nifp, nh->nh_d->cur_tx_ring);
		if (nm_ring_empty(ring)) {
			if (nh->nh_d->cur_tx_ring == nh->nh_d->last_tx_ring) {
				nh->nh_d->cur_tx_ring = nh->nh_d->first_tx_ring;

				rv = ioctl(nh->nh_d->fd, NIOCTXSYNC, NULL);
				if (rv == -1)
					err(1, "tx sync");
			} else {
				nh->nh_d->cur_tx_ring++;
			}
			continue;
		}

		for (;;) {
			if (nm_ring_empty(ring))
				break;
			slot = &ring->slot[ring->cur];
			slot->len = pkts[0].p_datalen;
			nm_pkt_copy(pkts[0].p_data, NETMAP_BUF(ring, slot->buf_idx), slot->len);
			ring->cur = nm_ring_next(ring, ring->cur);

			pkts++;
			if (--npkts == 0)
				break;
		}
		ring->head = ring->cur;

		rv = ioctl(nh->nh_d->fd, NIOCTXSYNC, NULL);
		if (rv == -1)
			err(1, "tx flush");
	}
}

struct producer *
netmap_producer(const char *iface)
{
	struct netmap_handle *nh;

	nh = netmap_handle_open(iface);
	if (nh == NULL)
		return (NULL);
	return (&nh->nh_producer);
}

static void
producer_netmap_produce(struct producer *producer, struct processor *processor, struct consumer *consumer)
{
	struct netmap_handle *nh;
	struct netmap_ring *ring;
	struct netmap_slot *slot;
	struct packet *pkt;
	struct pollfd pfd;
	bool need_sync;
	size_t npkts;
	int rv;

	nh = (struct netmap_handle *)((uintptr_t)producer - offsetof(struct netmap_handle, nh_producer));

	nh->nh_d->cur_rx_ring = nh->nh_d->first_rx_ring;

	need_sync = true;

	for (;;) {
		ring = NETMAP_RXRING(nh->nh_d->nifp, nh->nh_d->cur_rx_ring);
		if (nm_ring_empty(ring)) {
			if (nh->nh_d->cur_rx_ring == nh->nh_d->last_rx_ring) {
				nh->nh_d->cur_rx_ring = nh->nh_d->first_rx_ring;
				if (need_sync) {
					pfd.fd = nh->nh_d->fd;
					pfd.events = POLLIN;
					pfd.revents = 0;
					rv = poll(&pfd, 1, 0);
					if (rv == -1)
						err(1, "rx poll");
					need_sync = false;
				} else {
					if (nh->nh_d->cur_rx_ring == nh->nh_d->last_rx_ring)
						need_sync = true;
				}
			} else {
				nh->nh_d->cur_rx_ring++;
				need_sync = true;
			}
			continue;
		}

		need_sync = false;

		for (npkts = 0; npkts < NETMAP_PACKET_COUNT; npkts++) {
			pkt = &nh->nh_packets[npkts];
			if (nm_ring_empty(ring))
				break;
			slot = &ring->slot[ring->cur];
			pkt->p_data = NETMAP_BUF(ring, slot->buf_idx);
			pkt->p_datalen = slot->len;
			ring->cur = nm_ring_next(ring, ring->cur);
		}

		assert(npkts != 0);

		processor->p_process(processor, nh->nh_packets, npkts, consumer);

		ring->head = ring->cur;

		rv = ioctl(nh->nh_d->fd, NIOCRXSYNC, NULL);
		if (rv == -1)
			err(1, "rx sync");
	}
}

static struct netmap_handle *
netmap_handle_open(const char *iface)
{
	char ifname[7 + strlen(iface) + 1];
	struct netmap_handle *nh;

	STAILQ_FOREACH(nh, &netmap_handles, nh_link) {
		if (strcmp(iface, nh->nh_ifname) != 0)
			continue;
		return (nh);
	}

	snprintf(ifname, sizeof ifname, "netmap:%s", iface);

	nh = malloc(sizeof *nh);
	assert(nh != NULL);

	strlcpy(nh->nh_ifname, iface, sizeof nh->nh_ifname);

	nh->nh_d = nm_open(ifname, NULL, 0, NULL);
	if (nh->nh_d == NULL) {
		free(nh);
		return (NULL);
	}

	nh->nh_consumer.c_consume = consumer_netmap_consume;
	nh->nh_producer.p_produce = producer_netmap_produce;

	STAILQ_INSERT_TAIL(&netmap_handles, nh, nh_link);

	return (nh);
}
