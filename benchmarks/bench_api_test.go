// benchmarks/bench_api_test.go
// Benchmark suite for the DDoS platform control plane API.
// Measures: metrics endpoint latency, concurrent blocked IP listing,
// map aggregation throughput.
//
// Run with:
//   go test ./benchmarks/ -bench=. -benchmem -benchtime=10s
//   go test ./benchmarks/ -bench=BenchmarkMetrics -count=5
package benchmarks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/nsp/ddos-platform/pkg/types"
)

// ─── Stub server (mirrors control plane responses) ────────────────────────────

func newBenchServer(b *testing.B) *httptest.Server {
	b.Helper()

	// Pre-compute large payloads
	attackers := make([]types.AttackingIP, 20)
	for i := range attackers {
		attackers[i] = types.AttackingIP{
			IP:           fmt.Sprintf("%d.%d.%d.%d", i+1, i+2, i+3, i+4),
			TotalPackets: uint64(i * 100000),
			TotalBytes:   uint64(i * 64000000),
			SYNCount:     uint64(i * 1000),
			UDPCount:     uint64(i * 500),
			ICMPCount:    uint64(i * 100),
		}
	}

	blockedList := make([]types.BlockedIP, 100)
	for i := range blockedList {
		blockedList[i] = types.BlockedIP{
			IP:        fmt.Sprintf("10.%d.%d.%d", i/256, i%256, 1),
			Reason:    "syn_flood",
			BlockedAt: time.Now().Add(-time.Duration(i) * time.Minute),
		}
	}

	metricsPayload, _ := json.Marshal(types.Metrics{
		TotalPackets:      50_000_000,
		TotalBytes:        3_200_000_000,
		DroppedPackets:    250_000,
		PassedPackets:     49_750_000,
		SYNFloods:         1_200,
		UDPAmplifications: 300,
		ICMPFloods:        750,
		PPS:               125_000,
		BPS:               8_000_000_000,
		BlockedIPCount:    len(blockedList),
		TopAttackers:      attackers,
		Timestamp:         time.Now(),
	})
	blockedPayload, _ := json.Marshal(blockedList)
	attackerPayload, _ := json.Marshal(attackers)
	configPayload, _ := json.Marshal(types.Config{
		SYNRateLimit: 1000, UDPRateLimit: 5000, ICMPRateLimit: 100, Enabled: true,
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(metricsPayload)
	})
	mux.HandleFunc("/api/v1/blocked", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write(blockedPayload)
		case http.MethodPost:
			_, _ = w.Write([]byte(`{"status":"blocked"}`))
		case http.MethodDelete:
			_, _ = w.Write([]byte(`{"status":"unblocked"}`))
		}
	})
	mux.HandleFunc("/api/v1/attackers", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(attackerPayload)
	})
	mux.HandleFunc("/api/v1/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(configPayload)
	})
	return httptest.NewServer(mux)
}

// ─── HTTP benchmarks ──────────────────────────────────────────────────────────

func BenchmarkMetricsEndpoint(b *testing.B) {
	srv := newBenchServer(b)
	defer srv.Close()
	client := &http.Client{Timeout: 5 * time.Second}
	url := srv.URL + "/api/v1/metrics"

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		resp, err := client.Get(url)
		if err != nil {
			b.Fatalf("GET metrics: %v", err)
		}
		var m types.Metrics
		_ = json.NewDecoder(resp.Body).Decode(&m)
		resp.Body.Close()
	}
}

func BenchmarkMetricsEndpointParallel(b *testing.B) {
	srv := newBenchServer(b)
	defer srv.Close()
	url := srv.URL + "/api/v1/metrics"

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		client := &http.Client{Timeout: 5 * time.Second}
		for pb.Next() {
			resp, err := client.Get(url)
			if err != nil {
				b.Errorf("GET: %v", err)
				return
			}
			var m types.Metrics
			_ = json.NewDecoder(resp.Body).Decode(&m)
			resp.Body.Close()
		}
	})
}

func BenchmarkBlockedIPsEndpoint(b *testing.B) {
	srv := newBenchServer(b)
	defer srv.Close()
	client := &http.Client{Timeout: 5 * time.Second}
	url := srv.URL + "/api/v1/blocked"

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		resp, err := client.Get(url)
		if err != nil {
			b.Fatalf("GET blocked: %v", err)
		}
		var list []types.BlockedIP
		_ = json.NewDecoder(resp.Body).Decode(&list)
		resp.Body.Close()
	}
}

func BenchmarkBlockIP(b *testing.B) {
	srv := newBenchServer(b)
	defer srv.Close()
	client := &http.Client{Timeout: 5 * time.Second}
	url := srv.URL + "/api/v1/blocked"

	payload, _ := json.Marshal(map[string]interface{}{
		"ip": "1.2.3.4", "reason": 1,
	})

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		resp, err := client.Post(url, "application/json", bytes.NewReader(payload))
		if err != nil {
			b.Fatalf("POST blocked: %v", err)
		}
		resp.Body.Close()
	}
}

// ─── JSON marshaling benchmarks ───────────────────────────────────────────────

func BenchmarkMetricsJSONMarshal(b *testing.B) {
	m := types.Metrics{
		TotalPackets:   1_000_000,
		DroppedPackets: 5_000,
		PPS:            125_000,
		BPS:            8e9,
		TopAttackers:   make([]types.AttackingIP, 20),
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = json.Marshal(m)
	}
}

func BenchmarkMetricsJSONUnmarshal(b *testing.B) {
	m := types.Metrics{TotalPackets: 1_000_000, PPS: 125_000, BPS: 8e9}
	data, _ := json.Marshal(m)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var out types.Metrics
		_ = json.Unmarshal(data, &out)
	}
}

// ─── Concurrent access benchmarks ────────────────────────────────────────────

func BenchmarkConcurrentMetricsFetch(b *testing.B) {
	srv := newBenchServer(b)
	defer srv.Close()
	url := srv.URL + "/api/v1/metrics"

	const concurrency = 50
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Get(url)
			if err != nil {
				return
			}
			var m types.Metrics
			_ = json.NewDecoder(resp.Body).Decode(&m)
			resp.Body.Close()
		}()
	}
	wg.Wait()
}

// ─── IP conversion micro-benchmarks ──────────────────────────────────────────

func BenchmarkIPToUint32(b *testing.B) {
	data := []byte{192, 168, 1, 100}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	}
}

// ─── GlobalStats aggregation benchmark ───────────────────────────────────────

func BenchmarkGlobalStatsAggregation(b *testing.B) {
	// Simulate summing per-CPU stats (typical CPU count: 32–128)
	const numCPU = 64
	perCPU := make([]types.GlobalStats, numCPU)
	for i := range perCPU {
		perCPU[i] = types.GlobalStats{
			TotalPackets:      uint64(i * 1000),
			TotalBytes:        uint64(i * 64000),
			DroppedPackets:    uint64(i * 10),
			SYNFloods:         uint64(i),
			UDPAmplifications: uint64(i / 2),
			ICMPFloods:        uint64(i / 4),
			PassedPackets:     uint64(i * 990),
		}
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		agg := types.GlobalStats{}
		for _, v := range perCPU {
			agg.TotalPackets += v.TotalPackets
			agg.TotalBytes += v.TotalBytes
			agg.DroppedPackets += v.DroppedPackets
			agg.SYNFloods += v.SYNFloods
			agg.UDPAmplifications += v.UDPAmplifications
			agg.ICMPFloods += v.ICMPFloods
			agg.PassedPackets += v.PassedPackets
		}
		_ = agg
	}
}

// ─── AlertStore benchmark ─────────────────────────────────────────────────────

func BenchmarkAlertStoreAddAndList(b *testing.B) {
	// Import-free stub of AlertStore logic for benchmark isolation
	type alertRing struct {
		buf  []types.Alert
		max  int
		head int
		size int
	}

	ring := &alertRing{buf: make([]types.Alert, 500), max: 500}
	add := func(a types.Alert) {
		ring.buf[ring.head%ring.max] = a
		ring.head++
		if ring.size < ring.max {
			ring.size++
		}
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		add(types.Alert{Level: "warning", Type: "syn_flood", Message: "test"})
	}
}
