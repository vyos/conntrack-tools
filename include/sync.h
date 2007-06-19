#ifndef _SYNC_HOOKS_H_
#define _SYNC_HOOKS_H_

struct nethdr;
struct us_conntrack;

struct sync_mode {
	int internal_cache_flags;
	int external_cache_flags;
	struct cache_extra *internal_cache_extra;
	struct cache_extra *external_cache_extra;

	int  (*init)(void);
	void (*kill)(void);
	int  (*local)(int fd, int type, void *data);
	int  (*recv)(const struct nethdr *net);    /* recv callback */
	void (*send)(int type,			   /* send callback */
		     const struct nethdr *net,
		     struct us_conntrack *u);
};

extern struct sync_mode notrack;
extern struct sync_mode nack;

#endif
