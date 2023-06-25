# pktcat
```
Packet sniffer and sender for Linux. Writes packets received
from AF_PACKET raw socket to stdout in "[I/O] <iface> <pkthex>\n" format
and writes packets received from stdin in "<iface> <pkthex>\n" format to
the socket
  -r read packets from the socket and write to stdout
  -s read packets from stdin and write them to the socket
  -d prepend the output packet lines with direction - (I)nput/(O)utput
  -i use interface indexes instead of iterface names
  -o ignore outgoing
  -q do not print errors to stderr
  -b bind to the interface (name or index, depending on -i)
  -h this help
```
## usage example

send a packet to eth0 interface:
```
echo eth0 00deadbeaf000011233451100800450000320001000040007377c0a84301c0a843026d792d67656e746c652d6d6573736167652d746f2d7468652d776f726c64 | pktcat -s
```
recevice on all interfaces:
```
pktcat -r
eth0 00deadbeaf000011233451100800450000320001000040007377c0a84301c0a843026d792d67656e746c652d6d6573736167652d746f2d7468652d776f726c64
```
bind to eth0 and receive:
```
pktcat -rI eth0
```
both send and receive:
```
pktcat -rs
```
TODO:
wirte/find a pktprint utility witch would decode the packet and print it human readable format/json(?)... etc
like the tcpdump does but separate utility that receives the packet from stdin (and vice versa - json/human-readable -> hex)
