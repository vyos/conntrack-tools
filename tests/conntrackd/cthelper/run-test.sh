echo "Running test for oracle TNS port 1521"
./cthelper-test pcaps/oracle-tns-redirect.pcap tns tcp 1521

echo "Running test for oracle TNS port 1521"
./cthelper-test pcaps/oracle-tns-redirect.pcap tns tcp 1521 dnat

echo "Running test for NFSv3 UDP port 111"
./cthelper-test pcaps/nfsv3.pcap rpc udp 111

echo "Running test for NFSv3 TCP port 111"
./cthelper-test pcaps/nfsv3.pcap rpc tcp 111
