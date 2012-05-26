#!/bin/bash

UID=`id -u`
if [ $UID -ne 0 ]
then
	echo "Run this test as root"
	exit 1
fi

gcc test.c -o test
#
# XXX: module auto-load not support by nfnetlink_cttimeout yet :-(
#
modprobe nf_conntrack_ipv4
modprobe nf_conntrack_ipv6
modprobe nf_conntrack_proto_udplite
modprobe nf_conntrack_proto_sctp
modprobe nf_conntrack_proto_dccp
modprobe nf_conntrack_proto_gre
./test timeout
