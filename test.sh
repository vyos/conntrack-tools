CONNTRACK=conntrack

SRC=1.1.1.1
DST=2.2.2.2
SPORT=1980
DPORT=2005

case $1 in
	dump)
		# Setting dump mask
		echo "dump mask set to TUPLE"
		$CONNTRACK -A -m TUPLE
		$CONNTRACK -L
		echo "Press any key to continue..."
		read
		echo "dump mask set to TUPLE,COUNTERS"
		$CONNTRACK -A -m TUPLE,COUNTERS
		$CONNTRACK -L
		echo "Press any key to continue..."
		read
		echo "dump mask set to ALL"
		$CONNTRACK -A -m ALL
		$CONNTRACK -L
		echo "Press any key to continue..."
		read
		;;
	new)
		echo "creating a new conntrack"
		$CONNTRACK -I --orig-src $SRC --orig-dst $DST \
		 --reply-src $DST --reply-dst $SRC -p tcp \
		 --orig-port-src $SPORT  --orig-port-dst $DPORT \
		 --reply-port-src $DPORT --reply-port-dst $SPORT \
		--state LISTEN -u SEEN_REPLY -t 50
		;;
	get)
		echo "getting a conntrack"
		$CONNTRACK -G --orig-src $SRC --orig-dst $DST \
		-p tcp --orig-port-src $SPORT --orig-port-dst $DPORT \
		--reply-port-src $DPORT --reply-port-dst $SPORT
		;;
	change)
		echo "change a conntrack"
		$CONNTRACK -I --orig-src $SRC --orig-dst $DST \
		--reply-src $DST --reply-dst $SRC -p tcp \
		--orig-port-src $SPORT --orig-port-dst $DPORT \
		--reply-port-src $DPORT --reply-port-dst $SPORT \
		--state TIME_WAIT -u ASSURED,SEEN_REPLY -t 500
		;;
	delete)
		$CONNTRACK -D --orig-src $SRC --orig-dst $DST \
		-p tcp --orig-port-src $SPORT --orig-port-dst $DPORT
		;;
	output)
		proc=$(cat /proc/net/ip_conntrack | wc -l)
		netl=$($CONNTRACK -L | wc -l)
		count=$(cat /proc/sys/net/ipv4/netfilter/ip_conntrack_count)
		if [ $proc -ne $netl ]; then
			echo "proc is $proc and netl is $netl and count is $count"
		else
			if [ $proc -ne $count ]; then
				echo "proc is $proc and netl is $netl and count is $count"
			else
				echo "now $proc"
			fi
		fi
		;;
	*)
		echo "Usage: $0 [dump|new|change|delete|output]"
		;;
esac
