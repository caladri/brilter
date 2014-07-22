#ifndef	PIPE_H
#define	PIPE_H

struct consumer;
struct producer;
struct processor;

struct pipe;

struct pipe *pipe_start(struct producer *, struct processor *, struct consumer *);
void pipe_wait(struct pipe *);

#endif /* !PIPE_H */
