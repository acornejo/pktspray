# pktspray

Small utility to spray `tcp` packets, `udp` packets or `http` requests across a particular ip range and port range.
Intended as a small utility to aid in network testing, load testing and debugging.

It supports ipv4 and ipv6 ranges specified in cidr notation as defined
in RFC 4632 and RFC 4291 (i.e. 192.0.2.0/24 or 2001:db8::/32).

The size of the payload, destination port or number of connections in
parallel can be specified as options.

    Usage: pktspray [options] iprange

        i.e.: pktspray 192.168.0.1/24

    options:
    -http-method string
            http method for requests (default "POST")
    -http-path string
            http path for requests (default "/")
    -port string
            remote port [PORT] or range [MIN-MAX] (default "80")
    -proto string
            one of udp, tcp or http (default "tcp")
    -size int
            size of message payload in bytes (default 100)
    -sleep int
            sleep between consectuvive messages in milliseconds (default none)
    -spray int
            number of parallel connections (default 1)
    -timeout int
            timeout on connection in milliseconds (default 100)
