pktspray: pktspray.go
	CGO_ENABLED=0 go build -a -installsuffix cgo -ldflags '-s' pktspray.go

clean:
	rm -f pktspray
