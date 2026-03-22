//go:build linux

package main

import (
	"context"
	"log"
	"net/http"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/nsp/ddos-platform/pkg/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ─── Prometheus gauge/counter descriptors ────────────────────────────────────

const metricsNamespace = "ddos"

var (
	promTotalPackets = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Name:      "total_packets_total",
		Help:      "Total number of packets seen by the XDP program.",
	})
	promDroppedPackets = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Name:      "dropped_packets_total",
		Help:      "Total number of packets dropped by the XDP program.",
	})
	promPassedPackets = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Name:      "passed_packets_total",
		Help:      "Total number of packets passed by the XDP program.",
	})
	promTotalBytes = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Name:      "total_bytes_total",
		Help:      "Total bytes seen by the XDP program.",
	})
	promSYNFloods = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Name:      "syn_floods_total",
		Help:      "Number of SYN flood drop events.",
	})
	promUDPAmps = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Name:      "udp_amplification_total",
		Help:      "Number of UDP amplification drop events.",
	})
	promICMPFloods = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Name:      "icmp_floods_total",
		Help:      "Number of ICMP flood drop events.",
	})
	promPPS = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Name:      "packets_per_second",
		Help:      "Current packet rate (packets/second).",
	})
	promBPS = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Name:      "bits_per_second",
		Help:      "Current bit rate (bits/second).",
	})
	promBlockedIPs = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: metricsNamespace,
		Name:      "blocked_ips_count",
		Help:      "Number of currently blocked IP addresses.",
	})
)

// MetricsServer holds the Prometheus HTTP server and atomic metrics pointer.
type MetricsServer struct {
	srv     *http.Server
	manager *MapManager
	current atomic.Pointer[types.Metrics]
}

// NewMetricsServer creates a MetricsServer that collects BPF stats and exposes them.
func NewMetricsServer(addr string, manager *MapManager) *MetricsServer {
	// Register all metrics
	reg := prometheus.NewRegistry()
	for _, c := range []prometheus.Collector{
		promTotalPackets, promDroppedPackets, promPassedPackets,
		promTotalBytes, promSYNFloods, promUDPAmps, promICMPFloods,
		promPPS, promBPS, promBlockedIPs,
	} {
		if err := reg.Register(c); err != nil {
			log.Printf("prometheus register: %v", err)
		}
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	return &MetricsServer{
		manager: manager,
		srv: &http.Server{
			Addr:         addr,
			Handler:      mux,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 10 * time.Second,
		},
	}
}

// Start begins the Prometheus scrape server and background collection loop.
func (ms *MetricsServer) Start(ctx context.Context) {
	// Background collection goroutine
	go ms.collectLoop(ctx)

	log.Printf("Prometheus metrics server listening on %s", ms.srv.Addr)
	go func() {
		if err := ms.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("metrics server error: %v", err)
		}
	}()

	<-ctx.Done()
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = ms.srv.Shutdown(shutCtx)
}

// collectLoop polls BPF maps every second and updates Prometheus gauges.
func (ms *MetricsServer) collectLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m, err := ms.manager.CollectMetrics()
			if err != nil {
				log.Printf("collect metrics: %v", err)
				continue
			}
			ms.updatePrometheus(m)
			ms.current.Store(m)
		}
	}
}

// updatePrometheus pushes the latest snapshot to all registered gauges.
func (ms *MetricsServer) updatePrometheus(m *types.Metrics) {
	promTotalPackets.Set(float64(m.TotalPackets))
	promDroppedPackets.Set(float64(m.DroppedPackets))
	promPassedPackets.Set(float64(m.PassedPackets))
	promTotalBytes.Set(float64(m.TotalBytes))
	promSYNFloods.Set(float64(m.SYNFloods))
	promUDPAmps.Set(float64(m.UDPAmplifications))
	promICMPFloods.Set(float64(m.ICMPFloods))
	promPPS.Set(m.PPS)
	promBPS.Set(m.BPS)
	promBlockedIPs.Set(float64(m.BlockedIPCount))
}

// Latest returns the most recently collected Metrics snapshot.
func (ms *MetricsServer) Latest() *types.Metrics {
	p := ms.current.Load()
	if p == nil {
		return &types.Metrics{Timestamp: time.Now()}
	}
	return p
}

// metricsSize returns the size of types.Metrics for logging.
func metricsSize() int {
	return int(unsafe.Sizeof(types.Metrics{}))
}
