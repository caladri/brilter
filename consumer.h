#ifndef	CONSUMER_H
#define	CONSUMER_H

struct packet;

struct consumer {
	void (*c_consume)(struct consumer *, struct packet *, size_t);
};

#endif /* !CONSUMER_H */
