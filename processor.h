#ifndef	PROCESSOR_H
#define	PROCESSOR_H

struct consumer;
struct packet;

struct processor {
	void (*p_process)(struct processor *, struct packet *, size_t, struct consumer *);
};

static inline void
process_predicate(bool (*pass)(void *, const struct packet *), void *arg, struct packet *pkts, size_t npkts, struct consumer *consumer)
{
	size_t cnpkts, n;

	cnpkts = 0;
	for (n = 0; n < npkts; n++) {
		if (!pass(arg, &pkts[n]))
			continue;
		pkts[cnpkts++] = pkts[n];
	}

	if (cnpkts != 0)
		consumer->c_consume(consumer, pkts, cnpkts);
}

#endif /* !PROCESSOR_H */
