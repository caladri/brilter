#ifndef	CDEFS_H
#define	CDEFS_H

#define	container_of(p, t, m)	((t *)((uintptr_t)(p) - offsetof(t, m)))

/*
 * For doing unaligned field accesses, we want to be able
 * to get a pointer to the start of a field given the type
 * it's a member of.
 */
#define	field_ptr(p, t, m)	((void *)((uintptr_t)(p) + offsetof(t, m)))

#endif /* !CDEFS_H */
