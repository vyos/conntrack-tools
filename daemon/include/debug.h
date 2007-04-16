#ifndef _DEBUG_H
#define _DEBUG_H

#if 0
#define debug printf
#else
#define debug
#endif

#include <string.h>
#include <netinet/in.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

static inline void debug_ct(struct nf_conntrack *ct, char *msg)
{
	struct in_addr addr, addr2, addr3, addr4;

	debug("----%s (%p) ----\n", msg, ct);
	memcpy(&addr, 
	       nfct_get_attr(ct, ATTR_ORIG_IPV4_SRC), 
	       sizeof(u_int32_t));
	memcpy(&addr2, 
	       nfct_get_attr(ct, ATTR_ORIG_IPV4_DST), 
	       sizeof(u_int32_t));
	memcpy(&addr3, 
	       nfct_get_attr(ct, ATTR_REPL_IPV4_SRC), 
	       sizeof(u_int32_t));
	memcpy(&addr4, 
	       nfct_get_attr(ct, ATTR_REPL_IPV4_DST), 
	       sizeof(u_int32_t));

	debug("status: %x\n", nfct_get_attr_u32(ct, ATTR_STATUS));
	debug("l3:%d l4:%d ",
			nfct_get_attr_u8(ct, ATTR_ORIG_L3PROTO),
			nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO));
	debug("%s:%hu ->", inet_ntoa(addr),
			   ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC)));
	debug("%s:%hu\n",
			inet_ntoa(addr2),
			ntohs(nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST)));
	debug("l3:%d l4:%d ",
			nfct_get_attr_u8(ct, ATTR_REPL_L3PROTO),
			nfct_get_attr_u8(ct, ATTR_REPL_L4PROTO));
	debug("%s:%hu ->",
			inet_ntoa(addr3),
			ntohs(nfct_get_attr_u16(ct, ATTR_REPL_PORT_SRC)));
	debug("%s:%hu\n",
			inet_ntoa(addr4),
			ntohs(nfct_get_attr_u16(ct, ATTR_REPL_PORT_DST)));
	debug("-------------------------\n");
}

#endif
