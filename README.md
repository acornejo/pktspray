# pktspray

Small utility to spray `tcp` or `udp` packets to a particular ip range.
Intended as a small utility to aid in network testing and debugging.


It supports ipv4 and ipv6 ranges specified in cidr notation as defined
in RFC 4632 and RFC 4291 (i.e. 192.0.2.0/24 or 2001:db8::/32).

The size of the payload, destination port or number of packets per ip in
the ip-range can be specified as options. To increase the number of
packets sent per second you can use multiple connections in parallel.

    Usage: pktspray [options] iprange

        i.e.: pktspray 192.168.0.1/24

    options:
    -num int
            number of packets to send per ip (default 1)
    -parallel int
            number of connections to open in parallel (default 1)
    -port int
            remote port (default 80)
    -proto string
            protocol (udp or tcp) (default "tcp")
    -size int
            size of payload in bytes (default 100)
    -timeout int
            timeout in milliseconds for connection (default 1000)
