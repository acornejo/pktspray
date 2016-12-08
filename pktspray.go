package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
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

func SendUdp(address string, payload []byte, num int, timeout time.Duration, sleep time.Duration) {
	sent := 0
	for sent < num || num == 0 {
		conn, err := net.DialTimeout("udp", address, timeout)
		if err != nil {
			continue
		}
		defer conn.Close()
		for sent < num || num == 0 {
			conn.Write(payload)
			sent = sent + 1
			if sleep > 0 {
				time.Sleep(sleep)
			}
		}
	}
}

func SendTcp(address string, payload []byte, num int, timeout time.Duration, sleep time.Duration) {
	sent := 0
	for sent < num || num == 0 {
		conn, err := net.DialTimeout("tcp", address, timeout)
		sent = sent + 1
		if err != nil {
			continue
		}
		defer conn.Close()
		for sent < num || num == 0 {
			conn.Write(payload)
			sent = sent + 1
			if sleep > 0 {
				time.Sleep(sleep)
			}
		}
	}
}

func SendHttp(url string, payload []byte, num int, timeout time.Duration, sleep time.Duration) {
    // TODO: Investigate keep alives
	sent := 0
    method := "POST"
	client := http.Client{Timeout: timeout}
	for sent < num || num == 0 {
        req, err := http.NewRequest(method, url, bytes.NewBuffer(payload))
        if err != nil {
            fmt.Println(err)
            break
        }
        resp, err := client.Do(req)
        if err != nil {
            fmt.Println(err)
            break
        }
        resp.Body.Close()

		sent = sent + 1
		if sleep > 0 {
			time.Sleep(sleep)
		}
	}
}

func Spray(proto string, payload []byte, port int, iprange <-chan string, path string, timeout time.Duration, sleep time.Duration, num int, wg *sync.WaitGroup) {
	defer wg.Done()
	for address := range iprange {
		withPort := AddPort(address, port)
		if proto == "http" {
			httpAddr := fmt.Sprintf("http://%s%s", withPort, path)
			SendHttp(httpAddr, payload, num, timeout, sleep)
		} else if proto == "tcp" {
			SendTcp(withPort, payload, num, timeout, sleep)
		} else {
			SendUdp(withPort, payload, num, timeout, sleep)
		}
	}
}

func main() {
	proto := flag.String("proto", "tcp", "one of udp, tcp or http")
	port := flag.Int("port", 80, "remote port")
	size := flag.Int("size", 100, "size of payload in bytes")
	num := flag.Int("num", 1, "number of messages to send per ip, 0 for unlimited")
	sleep := flag.Int("sleep", 0, "time in milliseconds to wait between consecutive messages")
	timeout := flag.Int("timeout", 10, "timeout in milliseconds per message")
	parallel := flag.Int("parallel", 1, "number of addresses to try in parallel")
    // perAddress := flag.Int("perHttp", 1, "number of parallel requests per address")
	path := flag.String("path", "/", "path to use for http requests")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Println("Usage: pktspray [options] iprange\n")
		fmt.Println("    i.e.: pktspray 192.168.0.1/24\n")
		fmt.Println(" options:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *proto != "tcp" && *proto != "udp" && *proto != "http" {
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

	payload := []byte(strings.Repeat("0123456789", 1+(*size)/10)[:*size])

	addresses := IPRange(prefix, cidr)
	wg := &sync.WaitGroup{}
	wg.Add(*parallel)
	for i := 0; i < *parallel; i++ {
		go Spray(*proto, payload, *port, addresses, *path, time.Duration(*timeout)*time.Millisecond, time.Duration(*sleep)*time.Millisecond, *num, wg)
	}
	wg.Wait()
}
