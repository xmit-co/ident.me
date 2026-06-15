package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"syscall"

	"github.com/xmit-co/ident.me/backend/internal/metrics"
)

var (
	removePort = regexp.MustCompile(`^\[?([^\]]*)\]?:\d*$`)
)

var tracker = metrics.NewTracker(nil)

func serve(conn net.Conn) {
	ip := removePort.ReplaceAllString(conn.RemoteAddr().String(), "$1")
	if err := tracker.RecordRequest(context.Background(), ip, "telnet"); err != nil {
		log.Printf("Failed to record Telnet hit for %s (%v)", ip, err)
	}
	log.Printf("Resolved %s", ip)
	if _, err := conn.Write([]byte(ip)); err != nil {
		log.Printf("Failed to respond to %s (%s)", ip, err)
	}
	if err := conn.Close(); err != nil {
		log.Printf("Failed to close connection (%s)", err)
	}
}

func main() {
	go func() {
		server, err := net.Listen("tcp", ":23")
		if err != nil {
			log.Fatalln(err)
		}
		defer server.Close()

		for {
			conn, err := server.Accept()
			if err != nil {
				log.Printf("Failed to accept connection (%s)", err)
				continue
			}

			go serve(conn)
		}
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}
