#ifndef	PRODUCER_H
#define	PRODUCER_H

struct consumer;
struct packet;
struct processor;

struct producer {
	void (*p_produce)(struct producer *, struct processor *, struct consumer *);
};

#endif /* !PRODUCER_H */
