#ifndef	NETMAP_H
#define	NETMAP_H

struct consumer;
struct producer;

struct consumer *netmap_consumer(const char *);
struct producer *netmap_producer(const char *);

#endif /* !NETMAP_H */
