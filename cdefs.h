#ifndef	CDEFS_H
#define	CDEFS_H

#define	container_of(p, t, m)	((t *)((uintptr_t)(p) - offsetof(t, m)))

#endif /* !CDEFS_H */
