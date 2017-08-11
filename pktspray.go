package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const MaxPort = (1 << 16) - 1

func ParsePortRange(portRange string) (int, int, error) {
	portComponents := strings.Split(portRange, "-")
	if len(portComponents) == 1 {
		if portRange == "++" {
			return 0, MaxPort, nil
		} else if strings.HasSuffix(portRange, "+") {
			portStr := strings.TrimSuffix(portRange, "+")
			port, err := strconv.Atoi(portStr)
			if err != nil {
				return 0, 0, fmt.Errorf("port %s not integer", portStr)
			}
			return port, MaxPort, nil
		} else {
			port, err := strconv.Atoi(portRange)
			if err != nil {
				return 0, 0, fmt.Errorf("port %s not integer", portRange)
			}
			return port, port, nil
		}
	} else if len(portComponents) == 2 {
		portOne, err := strconv.Atoi(portComponents[0])
		if err != nil {
			return 0, 0, fmt.Errorf("port %s not integer", portComponents[0])
		}
		portTwo, err := strconv.Atoi(portComponents[1])
		if err != nil {
			return 0, 0, fmt.Errorf("port %s not integer", portComponents[1])
		}
		return portOne, portTwo, nil
	} else {
		return 0, 0, fmt.Errorf("%s is not a valid range", portRange)
	}
}

func Address(prefix net.IP, cidr int, index *big.Int) net.IP {
	prefixLength := len(prefix)
	maxBits := prefixLength * 8
	bitsLeft := maxBits - cidr

	ip := make([]byte, prefixLength)
	copy(ip, prefix)

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

	return ip
}

func IPRange(prefix net.IP, cidr int) <-chan net.IP {
	out := make(chan net.IP)
	bits := len(prefix)*8 - cidr
	go func() {
		defer close(out)

		for {
			if bits <= 1 {
				out <- prefix
			} else {
				i := big.NewInt(0)
				incr := big.NewInt(1)
				limit := big.NewInt(2)
				limit.Exp(limit, big.NewInt(int64(bits)), nil)
				limit.Sub(limit, big.NewInt(2))

				for limit.Cmp(i) > 0 {
					out <- Address(prefix, cidr, i)
					i = i.Add(i, incr)
				}
			}
		}
	}()
	return out
}

func PortRange(start int, stop int, step int) <-chan int {
	out := make(chan int)
	dist := stop - start
	go func() {
		defer close(out)

		next := start
		for {
			out <- next
			if dist > 0 {
				if step == 0 {
					next = start + rand.Intn(dist)
				} else {
					next = next + step
					if next > stop {
						next = start
					} else if next < start {
						next = stop
					}
				}
			}
		}
	}()
	return out
}

func IpPort(ip net.IP, port int) string {
	return net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
}

type SprayOptions struct {
	Ips        <-chan net.IP
	Ports      <-chan int
	Payload    []byte
	Timeout    time.Duration
	Sleep      time.Duration
	HttpMethod string
	HttpPath   string
}

// Interface to send a single packet on each call
type PacketSender interface {
	Send(ip net.IP, port int, options *SprayOptions)
	Close()
}

type UdpSender struct {
	lastAddr string
	conn     net.Conn
}

type TcpSender struct {
	lastAddr string
	conn     net.Conn
}

type HttpSender struct {
	lastAddr string
	client   *http.Client
	req      *http.Request
}

type PrintSender struct {
}

func (s UdpSender) Send(ip net.IP, port int, options *SprayOptions) {
	var err error
	address := IpPort(ip, port)
	if address != s.lastAddr {
		if s.conn != nil {
			s.conn.Close()
		}
		s.conn, err = net.DialTimeout("udp", address, options.Timeout)
		if err != nil {
			return
		}
		s.lastAddr = address
	}
	s.conn.Write(options.Payload)
}

func (s UdpSender) Close() {
	if s.conn != nil {
		s.conn.Close()
	}
}

func (s TcpSender) Send(ip net.IP, port int, options *SprayOptions) {
	var err error
	address := IpPort(ip, port)
	if address != s.lastAddr {
		if s.conn != nil {
			s.conn.Close()
		}
		s.conn, err = net.DialTimeout("tcp", address, options.Timeout)
		if err != nil {
			return
		}
		s.lastAddr = address
		// we return here, since tcp SYN counts as a packet.
		return
	}
	s.conn.Write(options.Payload)
}

func (s TcpSender) Close() {
	if s.conn != nil {
		s.conn.Close()
	}
}

func (s HttpSender) Send(ip net.IP, port int, options *SprayOptions) {
	// TODO: Investigate keep alives
	// client.Transport = &http.Transport{DisableKeepAlives: true}
	if s.client == nil {
		s.client = &http.Client{Timeout: options.Timeout}
	}
	if s.req == nil {
		var err error
		url := fmt.Sprintf("http://host:88%s", options.HttpPath)
		s.req, err = http.NewRequest(options.HttpMethod, url, bytes.NewBuffer(options.Payload))
		if err != nil {
			panic(err)
		}
	}

	address := IpPort(ip, port)
	if address != s.lastAddr {
		s.req.Host = address
		s.req.URL.Host = s.req.Host
		s.lastAddr = address
	}
	resp, err := s.client.Do(s.req)
	if err != nil {
		return
	}

	ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	s.req.Body, err = s.req.GetBody()
	if err != nil {
		panic(err)
	}
}

func (s HttpSender) Close() {}

func (s PrintSender) Send(ip net.IP, port int, options *SprayOptions) {
	fmt.Println("spraying", IpPort(ip, port))
}

func (s PrintSender) Close() {
	fmt.Println("closing")
}

func Spray(sender PacketSender, options *SprayOptions, wg *sync.WaitGroup) {
	defer wg.Done()
	defer sender.Close()
	for ip := range options.Ips {
		port := <-options.Ports
		sender.Send(ip, port, options)
		if options.Sleep > 0 {
			time.Sleep(options.Sleep)
		}
	}
}

func main() {
	spray := flag.Int("spray", 1, "number of parallel connections")
	proto := flag.String("proto", "tcp", "one of udp, tcp or http")
	port := flag.String("port", "80", "remote port [PORT] or range [MIN-MAX]")
	size := flag.Int("size", 100, "size of message payload in bytes")
	sleep := flag.Int("sleep", 0, "sleep between consectuvive messages in milliseconds (default none)")
	timeout := flag.Int("timeout", 100, "timeout on connection in milliseconds")
	httpPath := flag.String("http-path", "/", "http path for requests")
	httpMethod := flag.String("http-method", "POST", "http method for requests")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Println("Usage: pktspray [options] iprange\n")
		fmt.Println("    i.e.: pktspray 192.168.0.1/24\n")
		fmt.Println(" options:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	_, ipnet, err := net.ParseCIDR(flag.Arg(0))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	cidr, _ := ipnet.Mask.Size()

	minPort, maxPort, err := ParsePortRange(*port)
	if err != nil {
		fmt.Println("can't parse port range:", err)
		os.Exit(1)
	}

	var sender PacketSender
	if *proto == "http" {
		sender = HttpSender{}
	} else if *proto == "tcp" {
		sender = TcpSender{}
	} else if *proto == "udp" {
		sender = UdpSender{}
	} else if *proto == "print" {
		// for debugging
		sender = PrintSender{}
	} else {
		fmt.Println("unsuported protocol", *proto)
		os.Exit(1)
	}

	payload := []byte(strings.Repeat("0123456789", 1+(*size)/10)[:*size])

	options := &SprayOptions{
		Ips:        IPRange(ipnet.IP, cidr),
		Ports:      PortRange(minPort, maxPort, 1),
		Payload:    payload,
		Timeout:    time.Duration(*timeout) * time.Millisecond,
		Sleep:      time.Duration(*sleep) * time.Millisecond,
		HttpMethod: *httpMethod,
		HttpPath:   *httpPath,
	}

	wg := &sync.WaitGroup{}
	wg.Add(*spray)
	for i := 0; i < *spray; i++ {
		go Spray(sender, options, wg)
	}
	wg.Wait()
}
