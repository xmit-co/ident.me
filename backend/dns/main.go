package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/miekg/dns"
	"github.com/xmit-co/ident.me/backend/internal/metrics"
)

var (
	tracker      = metrics.NewTracker(nil)
	ipv4Suffixes = []string{".lit4.ident.me.", ".lit4.tnedi.me."}
	ipv6Suffixes = []string{".lit6.ident.me.", ".lit6.tnedi.me."}
)

// parseIPFromName extracts an IP address encoded in a DNS name.
// For IPv4: 1-2-3-4.lit4.ident.me -> 1.2.3.4
// For IPv6: --1.lit6.ident.me -> ::1
func parseIPFromName(name string) net.IP {
	name = strings.ToLower(name)
	if ip := extractIP(name, ipv4Suffixes, "."); ip != nil {
		return ip.To4()
	}
	return extractIP(name, ipv6Suffixes, ":")
}

func extractIP(name string, suffixes []string, sep string) net.IP {
	for _, suffix := range suffixes {
		if strings.HasSuffix(name, suffix) {
			prefix := strings.TrimSuffix(name, suffix)
			parts := strings.Split(prefix, ".")
			ipStr := strings.ReplaceAll(parts[len(parts)-1], "-", sep)
			if ip := net.ParseIP(ipStr); ip != nil {
				return ip
			}
		}
	}
	return nil
}

func handle(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	name := r.Question[0].Name
	m.Authoritative = true
	if r.RecursionDesired {
		m.RecursionAvailable = true
	}

	var a net.IP

	// First, try to parse an IP from the query name
	if parsedIP := parseIPFromName(name); parsedIP != nil {
		a = parsedIP
	} else {
		// Fall back to the client's IP
		if ip, ok := w.RemoteAddr().(*net.UDPAddr); ok {
			a = ip.IP
		} else if ip, ok := w.RemoteAddr().(*net.TCPAddr); ok {
			a = ip.IP
		}
	}

	if a.To4() != nil {
		m.Answer = append(m.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 0},
			A:   a,
		})
	} else {
		m.Answer = append(m.Answer, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 0},
			AAAA: a,
		})
	}
	if a != nil {
		if err := tracker.RecordRequest(context.Background(), a.String(), "dns"); err != nil {
			log.Printf("Failed to record DNS hit for %v (%v)", a, err)
		}
	}
	w.WriteMsg(m)
	log.Printf("Resolved %v", a)
}

func main() {
	dns.HandleFunc(".", handle)
	go func() {
		if err := (&dns.Server{Addr: ":53", Net: "udp", ReusePort: true}).ListenAndServe(); err != nil {
			log.Fatalf("Failed to listen on UDP (%s)", err)
		}
	}()
	go func() {
		if err := (&dns.Server{Addr: ":53", Net: "tcp", ReusePort: true}).ListenAndServe(); err != nil {
			log.Fatalf("Failed to listen on TCP (%s)", err)
		}
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}
