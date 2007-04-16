/*
 * (C) 2006 by Pablo Neira Ayuso <pablo@netfilter.org>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#if 0
#define dprintf printf
#else
#define dprintf
#endif

int nlh_payload_host2network(struct nfattr *nfa, int len)
{
	struct nfattr *__nfa;

	while (NFA_OK(nfa, len)) {

		dprintf("type=%d nfalen=%d len=%d [%s]\n", 
			nfa->nfa_type & 0x7fff,
			nfa->nfa_len, len,
			nfa->nfa_type & NFNL_NFA_NEST ? "NEST":"");

		if (nfa->nfa_type & NFNL_NFA_NEST) {
			if (NFA_PAYLOAD(nfa) > len)
				return -1;

			if (nlh_payload_host2network(NFA_DATA(nfa), 
						     NFA_PAYLOAD(nfa)) == -1)
				return -1;
		}

		__nfa = NFA_NEXT(nfa, len);

		nfa->nfa_type = htons(nfa->nfa_type);
		nfa->nfa_len  = htons(nfa->nfa_len);

		nfa = __nfa; 
	}
	return 0;
}

int nlh_host2network(struct nlmsghdr *nlh)
{
	struct nfgenmsg *nfhdr = NLMSG_DATA(nlh);
	struct nfattr *cda[CTA_MAX];
	unsigned int min_len = NLMSG_SPACE(sizeof(struct nfgenmsg));
	unsigned int len = nlh->nlmsg_len - NLMSG_ALIGN(min_len);

	nlh->nlmsg_len   = htonl(nlh->nlmsg_len);
	nlh->nlmsg_type  = htons(nlh->nlmsg_type);
	nlh->nlmsg_flags = htons(nlh->nlmsg_flags);
	nlh->nlmsg_seq   = htonl(nlh->nlmsg_seq);
	nlh->nlmsg_pid   = htonl(nlh->nlmsg_pid);

	nfhdr->res_id    = htons(nfhdr->res_id);

	return nlh_payload_host2network(NFM_NFA(NLMSG_DATA(nlh)), len);
}

int nlh_payload_network2host(struct nfattr *nfa, int len)
{
	nfa->nfa_type = ntohs(nfa->nfa_type);
	nfa->nfa_len  = ntohs(nfa->nfa_len);

	while(NFA_OK(nfa, len)) {

                dprintf("type=%d nfalen=%d len=%d [%s]\n", 
		        nfa->nfa_type & 0x7fff, 
		        nfa->nfa_len, len, 
		        nfa->nfa_type & NFNL_NFA_NEST ? "NEST":"");

		if (nfa->nfa_type & NFNL_NFA_NEST) {
			if (NFA_PAYLOAD(nfa) > len)
				return -1;

			if (nlh_payload_network2host(NFA_DATA(nfa),
						     NFA_PAYLOAD(nfa)) == -1)
				return -1;
		}

		nfa = NFA_NEXT(nfa,len);

		if (len < NFA_LENGTH(0))
			break;

		nfa->nfa_type = ntohs(nfa->nfa_type);
		nfa->nfa_len  = ntohs(nfa->nfa_len);
	}
	return 0;
}

int nlh_network2host(struct nlmsghdr *nlh)
{
	struct nfgenmsg *nfhdr = NLMSG_DATA(nlh);
	struct nfattr *cda[CTA_MAX];
	unsigned int min_len = NLMSG_SPACE(sizeof(struct nfgenmsg));
	unsigned int len = ntohl(nlh->nlmsg_len) - NLMSG_ALIGN(min_len);

	nlh->nlmsg_len   = ntohl(nlh->nlmsg_len);
	nlh->nlmsg_type  = ntohs(nlh->nlmsg_type);
	nlh->nlmsg_flags = ntohs(nlh->nlmsg_flags);
	nlh->nlmsg_seq   = ntohl(nlh->nlmsg_seq);
	nlh->nlmsg_pid   = ntohl(nlh->nlmsg_pid);

	nfhdr->res_id    = ntohs(nfhdr->res_id);

	return nlh_payload_network2host(NFM_NFA(NLMSG_DATA(nlh)), len);
}
