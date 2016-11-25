package main

import (
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type IPFamily struct {
	AddressFormat string
	PortFormat    string
	Bits          int
}

var IPV4 = &IPFamily{"%d.%d.%d.%d", "%s:%d", 32}
var IPV6 = &IPFamily{"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", "[%s]:%d", 128}

func Address(format string, maxBits int, prefix []byte, cidr int, index *big.Int) (string, error) {
	if len(prefix)*8 != maxBits {
		return "", errors.New(fmt.Sprint("parsed ", len(prefix), " octets, expected ", maxBits, " bits"))
	}

	if cidr > maxBits {
		return "", errors.New(fmt.Sprint("cidr exceeds ", maxBits, " bits"))
	}

	ip := make([]byte, len(prefix))
	copy(ip, prefix)

	if cidr < maxBits {
		bitsLeft := maxBits - cidr
		maxNum := big.NewInt(2)
		maxNum.Exp(maxNum, big.NewInt(int64(bitsLeft)), nil)
		maxNum.Sub(maxNum, big.NewInt(2))
		if index.Cmp(maxNum) >= 0 {
			return "", errors.New(fmt.Sprint("cidr ", cidr, " can only generate up to ", maxNum, " addresses"))
		}
		x := big.NewInt(1)
		x.Add(x, index)
		suffix := x.Bytes()
		for i, j := len(ip)-1, len(suffix)-1; i >= 0 && j >= 0 && bitsLeft > 0; i, j, bitsLeft = i-1, j-1, bitsLeft-8 {
			mask := byte(0xFF)
			if bitsLeft < 8 {
				mask = 1<<uint(bitsLeft) - 1
			}
			ip[i] |= suffix[j] & mask
		}
	}

	var printArgs []interface{} = make([]interface{}, len(ip))
	for i, d := range ip {
		printArgs[i] = d
	}
	return fmt.Sprintf(format, printArgs...), nil
}

func IPAddress(prefix []byte, cidr int, index *big.Int) (string, error) {
	l := len(prefix)
	if l == 4 {
		return Address(IPV4.AddressFormat, IPV4.Bits, prefix, cidr, index)
	} else if l == 16 {
		return Address(IPV6.AddressFormat, IPV6.Bits, prefix, cidr, index)
	} else {
		return "", errors.New(fmt.Sprint("invalid prefix length", l))
	}
}

func IPRange(prefix []byte, cidr int) <-chan string {
	out := make(chan string)
	go func() {
		defer close(out)

		bits := len(prefix)*8 - cidr

		i := big.NewInt(0)
		incr := big.NewInt(1)

		if bits <= 1 {
			address, err := IPAddress(prefix, cidr, incr)
			if err != nil {
				panic(err)
			}
			out <- address
		}

		limit := big.NewInt(2)
		limit.Exp(limit, big.NewInt(int64(bits)), nil)
		limit.Sub(limit, big.NewInt(2))

		for limit.Cmp(i) > 0 {
			address, err := IPAddress(prefix, cidr, i)
			if err != nil {
				panic(err)
			}
			out <- address

			i = i.Add(i, incr)
		}
	}()
	return out
}

func AddPort(address string, port int) string {
	isIPV4 := strings.Count(address, ".") == 3
	if isIPV4 {
		return fmt.Sprintf(IPV4.PortFormat, address, port)
	} else {
		return fmt.Sprintf(IPV6.PortFormat, address, port)
	}
}

func Spray(proto string, payload string, port int, iprange <-chan string, timeout int, num int, wg *sync.WaitGroup) {
	defer wg.Done()
	for address := range iprange {
		tries := num
		for tries > 0 {
			conn, err := net.DialTimeout(proto, AddPort(address, port), time.Duration(timeout)*time.Millisecond)
			if proto == "tcp" {
				// for tcp, dialing requires sending a packet (actually two packets)
				tries = tries - 1
			}
			if err != nil {
				continue
			} else {
				defer conn.Close()
				for tries > 0 {
					fmt.Fprint(conn, payload)
					tries = tries - 1
				}
			}
		}
	}
}

func main() {
	proto := flag.String("proto", "tcp", "protocol (udp or tcp)")
	port := flag.Int("port", 80, "remote port")
	size := flag.Int("size", 100, "size of payload in bytes")
	num := flag.Int("num", 1, "number of packets to send per ip")
	timeout := flag.Int("timeout", 10, "timeout in milliseconds per tcp connection")
	parallel := flag.Int("parallel", 1, "number of connections to open in parallel")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Println("Usage: pktspray [options] iprange\n")
		fmt.Println("    i.e.: pktspray 192.168.0.1/24\n")
		fmt.Println(" options:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *proto != "tcp" && *proto != "udp" {
		fmt.Println("unsuported protocol", *proto)
		os.Exit(1)
	}

	_, ipnet, err := net.ParseCIDR(flag.Arg(0))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	prefix := ipnet.IP
	cidr, _ := ipnet.Mask.Size()

	payload := strings.Repeat("lorem ipsum ", 1+(*size)/12)[:*size]

	addresses := IPRange(prefix, cidr)
	wg := &sync.WaitGroup{}
	wg.Add(*parallel)
	for i := 0; i < *parallel; i++ {
		go Spray(*proto, payload, *port, addresses, *timeout, *num, wg)
	}
	wg.Wait()
}
