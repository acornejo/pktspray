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
      -count int
            number of messages to send to an address in parallel (default 1)
      -num int
            number of messages to send to each address (default unlimited)
      -path string
            path to use for http requests (default "/")
      -port int
            remote port (default 80)
      -proto string
            one of udp, tcp or http (default "tcp")
      -size int
            size of message payload in bytes (default 100)
      -sleep int
            time in milliseconds to wait between consecutive messages (default none)
      -spray int
            number of addresses to connect to in parallel (default 1)
      -timeout int
            timeout in milliseconds per message (default 100)
