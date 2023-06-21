# pktcat

packet sniffer and sender for linux.
Writes packets received from AF_PACKET raw socket to stdout in
"\<iface\> \<pkthex\>\\n" format and writes packets received from stdin in
"\<iface\> <pkthex\>\\n" format to the socket.

usage example
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
