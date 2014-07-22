#include <assert.h>
#include <err.h>
#include <pthread.h>
#include <stdlib.h>

#include "pipe.h"
#include "producer.h"

struct pipe {
	pthread_t p_td;
	struct producer *p_producer;
	struct processor *p_processor;
	struct consumer *p_consumer;
};

static void *pipe_main(void *);

struct pipe *
pipe_start(struct producer *producer, struct processor *processor, struct consumer *consumer)
{
	struct pipe *p;
	int error;

	assert(producer != NULL);
	assert(processor != NULL);
	assert(consumer != NULL);

	p = malloc(sizeof *p);
	assert(p != NULL);
	p->p_producer = producer;
	p->p_processor = processor;
	p->p_consumer = consumer;

	error = pthread_create(&p->p_td, NULL, pipe_main, p);
	if (error != 0) {
		warnc(error, "pthread_create");
		free(p);
		return (NULL);
	}

	return (p);
}

void
pipe_wait(struct pipe *p)
{
	int error;

	error = pthread_join(p->p_td, NULL);
	if (error != 0)
		warnc(error, "pthread_join");
}

static void *
pipe_main(void *arg)
{
	struct pipe *p;

	p = arg;

	for (;;) {
		p->p_producer->p_produce(p->p_producer, p->p_processor, p->p_consumer);
	}
}
