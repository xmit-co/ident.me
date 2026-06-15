package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/openrdap/rdap"
	"github.com/oschwald/maxminddb-golang/v2"
	"github.com/xmit-co/ident.me/backend/internal/metrics"
	"github.com/quic-go/quic-go/http3"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/acme/autocert"
)

type dbRecord struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Continent struct {
		Code string `maxminddb:"code"`
	} `maxminddb:"continent"`
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	Location struct {
		Latitude    float64 `maxminddb:"latitude"`
		Longitude   float64 `maxminddb:"longitude"`
		TimeZone    string  `maxminddb:"time_zone"`
		WeatherCode string  `maxminddb:"weather_code"`
	} `maxminddb:"location"`
	Postal struct {
		Code string `maxminddb:"code"`
	} `maxminddb:"postal"`
	Traits struct {
		AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
		AutonomousSystemNumber       uint   `maxminddb:"autonomous_system_number"`
		ISP                          string `maxminddb:"isp"`
		UserType                     string `maxminddb:"user_type"`
	} `maxminddb:"traits"`
}

type JSON struct {
	IP        string  `json:"ip,omitempty"`
	Hostname  string  `json:"hostname,omitempty"`
	ASO       string  `json:"aso,omitempty"`
	ASN       uint    `json:"asn,omitempty"`
	Type      string  `json:"type,omitempty"`
	Continent string  `json:"continent,omitempty"`
	CC        string  `json:"cc,omitempty"`
	Country   string  `json:"country,omitempty"`
	City      string  `json:"city,omitempty"`
	Postal    string  `json:"postal,omitempty"`
	Latitude  float64 `json:"latitude,omitempty"`
	Longitude float64 `json:"longitude,omitempty"`
	TZ        string  `json:"tz,omitempty"`
	Weather   string  `json:"weather,omitempty"`
}

func lookupAddr(ip string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	r := &net.Resolver{}
	names, err := r.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

func toJSON(ip string, record dbRecord) (JSON, error) {
	return JSON{
		IP:        ip,
		Hostname:  lookupAddr(ip),
		ASO:       record.Traits.AutonomousSystemOrganization,
		ASN:       record.Traits.AutonomousSystemNumber,
		Continent: record.Continent.Code,
		CC:        record.Country.ISOCode,
		Country:   record.Country.Names["en"],
		City:      record.City.Names["en"],
		Postal:    record.Postal.Code,
		Latitude:  record.Location.Latitude,
		Longitude: record.Location.Longitude,
		TZ:        record.Location.TimeZone,
		Weather:   record.Location.WeatherCode,
		Type:      record.Traits.UserType,
	}, nil
}

var (
	domains = []string{
		"a.ident.me", "any.ident.me", "4.ident.me", "6.ident.me", "ident.me", "ip4.ident.me", "ip6.ident.me", "ipv4.ident.me", "ipv6.ident.me", "v4.ident.me", "v6.ident.me",
		"a.tnedi.me", "any.tnedi.me", "4.tnedi.me", "6.tnedi.me", "tnedi.me", "ip4.tnedi.me", "ip6.tnedi.me", "ipv4.tnedi.me", "ipv6.tnedi.me", "v4.tnedi.me", "v6.tnedi.me",
	}
)

func ip(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	return host
}

func headers(w http.ResponseWriter) {
	w.Header().Set("Alt-Svc", "h3=\":443\"; ma=3600")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
}

type RDAPHTTP struct {
	URL    string      `json:"url"`
	Status int         `json:"status"`
	Body   interface{} `json:"body"`
}

func main() {
	bg := context.Background()
	tracker := metrics.NewTracker(nil)
	red := tracker.Client()
	rdapc := rdap.Client{}

	db, err := maxminddb.Open("/var/lib/dbip.mmdb")
	if err != nil {
		panic(err)
	}
	defer db.Close()
	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(domains...),
		Cache:      autocert.DirCache("/certs"),
	}

	router := http.NewServeMux()

	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		headers(w)
		accept := r.Header.Get("Accept")
		if strings.Count(r.Host, ".") == 1 && (accept == "text/html" || strings.HasPrefix(accept, "text/html,")) {
			w.Header().Set("Location", "https://www."+r.Host)
			w.WriteHeader(http.StatusMovedPermanently)
		}
		clientIP := ip(r)
		if err := tracker.RecordRequest(bg, clientIP, r.UserAgent()); err != nil {
			fmt.Printf("Error tracking request: %v\n", err)
		}
		w.Write([]byte(clientIP))
	})

	router.HandleFunc("/.json", func(w http.ResponseWriter, r *http.Request) {
		headers(w)
		clientIP := ip(r)
		if err := tracker.RecordRequest(bg, clientIP, r.UserAgent()); err != nil {
			fmt.Printf("Error tracking request: %v\n", err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"address": "` + clientIP + `"}`))
	})

	router.HandleFunc("/.xml", func(w http.ResponseWriter, r *http.Request) {
		headers(w)
		w.Header().Set("Content-Type", "application/xml")
		clientIP := ip(r)
		if err := tracker.RecordRequest(bg, clientIP, r.UserAgent()); err != nil {
			fmt.Printf("Error tracking request: %v\n", err)
		}
		w.Write([]byte(`<address>` + clientIP + `</address>`))
	})

	router.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		headers(w)
		w.Header().Set("Content-Type", "application/json")
		clientIP := ip(r)
		if err := tracker.RecordRequest(bg, clientIP, r.UserAgent()); err != nil {
			fmt.Printf("Error tracking request: %v\n", err)
		}
		pip, err := netip.ParseAddr(clientIP)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var record dbRecord
		if err := db.Lookup(pip).Decode(&record); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		j, err := toJSON(clientIP, record)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		bytes, err := json.Marshal(j)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(bytes)
	})

	router.HandleFunc("/n", func(w http.ResponseWriter, r *http.Request) {
		headers(w)
		i, err := red.Incr(r.Context(), "counter").Result()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			_, _ = w.Write([]byte(fmt.Sprintf("%016x", i)))
		}
	})

	router.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		headers(w)
		w.Header().Set("Content-Type", "application/json")

		now := time.Now().UTC()
		pipe := red.Pipeline()

		// Get last 24 hours of hourly stats
		hourlyStats := make([]int64, 24)
		hourlyUniqueStats := make([]int64, 24)
		for i := 0; i < 24; i++ {
			hour := strconv.FormatInt(now.Unix()/3600-int64(i), 10)
			pipe.Get(r.Context(), "h:"+hour)
			pipe.PFCount(r.Context(), "ph:"+hour)
		}

		// Get last 90 days of daily stats
		dailyStats := make([]int64, 90)
		dailyUniqueStats := make([]int64, 90)
		dailyIPv4Stats := make([]int64, 90)
		dailyIPv6Stats := make([]int64, 90)
		for i := 0; i < 90; i++ {
			day := strconv.FormatInt(now.Unix()/86400-int64(i), 10)
			pipe.Get(r.Context(), "d:"+day)
			pipe.Get(r.Context(), "d4:"+day)
			pipe.Get(r.Context(), "d6:"+day)
			pipe.PFCount(r.Context(), "pd:"+day)
		}

		results, err := pipe.Exec(r.Context())
		if err != nil && err != redis.Nil {
			fmt.Printf("Error getting stats: %v\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		resultIdx := 0
		for i := 0; i < 24; i++ {
			hourlyStats[i] = metrics.GetInt64(results[resultIdx])
			resultIdx++
			hourlyUniqueStats[i] = metrics.GetInt64(results[resultIdx])
			resultIdx++
		}
		for i := 0; i < 90; i++ {
			dailyStats[i] = metrics.GetInt64(results[resultIdx])
			resultIdx++
			dailyIPv4Stats[i] = metrics.GetInt64(results[resultIdx])
			resultIdx++
			dailyIPv6Stats[i] = metrics.GetInt64(results[resultIdx])
			resultIdx++
			dailyUniqueStats[i] = metrics.GetInt64(results[resultIdx])
			resultIdx++
		}

		uaCount := tracker.UserAgentCounts()

		stats := map[string]interface{}{
			"hourly": map[string]interface{}{
				"reqs": hourlyStats,
				"ips":  hourlyUniqueStats,
			},
			"daily": map[string]interface{}{
				"reqs": dailyStats,
				"ipv4": dailyIPv4Stats,
				"ipv6": dailyIPv6Stats,
				"ips":  dailyUniqueStats,
			},
			"ua": uaCount,
		}
		json.NewEncoder(w).Encode(stats)
	})

	router.HandleFunc("/headers", func(w http.ResponseWriter, r *http.Request) {
		headers(w)
		w.Header().Set("Content-Type", "text/plain")
		r.Header.Write(w)
	})

	router.HandleFunc("/rdap/", func(w http.ResponseWriter, r *http.Request) {
		headers(w)
		w.Header().Set("Content-Type", "application/json")

		target := strings.TrimPrefix(r.URL.Path, "/rdap/")
		if target == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		req := rdap.NewAutoRequest(target)
		if req == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		req = req.WithContext(r.Context())

		resp, err := rdapc.Do(req)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte(err.Error()))
			return
		}

		// Write all HTTP response resps to the response writer
		resps := make([]RDAPHTTP, len(resp.HTTP))
		for i, h := range resp.HTTP {
			var body interface{}
			if err := json.Unmarshal(h.Body, &body); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(err.Error()))
				return
			}
			resps[i] = RDAPHTTP{
				URL:    h.URL,
				Status: h.Response.StatusCode,
				Body:   body,
			}
		}
		w.WriteHeader(http.StatusOK)
		bytes, err := json.Marshal(resps)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}
		w.Write(bytes)
	})

	serverTLS := &http.Server{
		Handler:      router,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  65 * time.Second,
	}

	go func() {
		server3 := &http3.Server{
			Addr:    ":443",
			Handler: router,
			TLSConfig: &tls.Config{
				GetCertificate: certManager.GetCertificate,
			},
		}

		if err := server3.ListenAndServe(); err != nil {
			panic(err)
		}
	}()

	go func() {
		server80 := &http.Server{
			Addr:         ":80",
			Handler:      certManager.HTTPHandler(router),
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  65 * time.Second,
		}

		if err := server80.ListenAndServe(); err != nil {
			panic(err)
		}
	}()

	if err := serverTLS.Serve(certManager.Listener()); err != nil {
		panic(err)
	}
}
