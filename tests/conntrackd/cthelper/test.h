#ifndef _CTHELPER_TEST_H_
#define _CTHELPER_TEST_H_

struct cthelper_test_stats {
	int	pkts;
	int	pkt_mismatch_proto;
	int	pkt_mismatch_port;
	int	ct_expect_created;
};

extern struct cthelper_test_stats cthelper_test_stats;

#endif
