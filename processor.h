#ifndef	PROCESSOR_H
#define	PROCESSOR_H

struct consumer;
struct packet;

struct processor {
	void (*p_process)(struct processor *, struct packet *, size_t, struct consumer *);
};

#endif /* !PROCESSOR_H */
