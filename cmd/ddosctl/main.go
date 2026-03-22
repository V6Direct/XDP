// cmd/ddosctl/main.go
// ddosctl – Command-line management tool for the DDoS Mitigation Platform.
//
// Usage:
//   ddosctl [--api URL] <command> [args...]
//
// Commands:
//   status                   Show live stats
//   block   <ip> [reason]    Block an IP (reason: syn|udp|icmp, default syn)
//   unblock <ip>             Remove a block
//   blocked                  List all blocked IPs
//   whitelist  <ip>          Add IP to whitelist
//   unwhitelist <ip>         Remove IP from whitelist
//   attackers                Show top attacking IPs
//   config                   Show current XDP config
//   set-config               Update rate limits
//   enable                   Enable XDP mitigation
//   disable                  Disable XDP mitigation
//   watch                    Live-updating stats (refreshes every second)
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/nsp/ddos-platform/pkg/types"
)

var (
	apiURL  = flag.String("api", envOrDefault("DDOS_API", "http://localhost:8080"), "Control plane API URL")
	jsonOut = flag.Bool("json", false, "Output raw JSON")
)

func main() {
	flag.Parse()
	args := flag.Args()

	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	cmd := args[0]
	rest := args[1:]

	client := &apiClient{
		base: strings.TrimRight(*apiURL, "/"),
		http: &http.Client{Timeout: 10 * time.Second},
	}

	var err error
	switch cmd {
	case "status":
		err = cmdStatus(client)
	case "block":
		err = cmdBlock(client, rest)
	case "unblock":
		err = cmdUnblock(client, rest)
	case "blocked":
		err = cmdBlocked(client)
	case "whitelist":
		err = cmdWhitelist(client, rest)
	case "unwhitelist":
		err = cmdUnwhitelist(client, rest)
	case "attackers":
		err = cmdAttackers(client)
	case "config":
		err = cmdConfig(client)
	case "set-config":
		err = cmdSetConfig(client, rest)
	case "enable":
		err = cmdSetEnabled(client, true)
	case "disable":
		err = cmdSetEnabled(client, false)
	case "watch":
		err = cmdWatch(client)
	case "help", "--help", "-h":
		printUsage()
	default:
		fatalf("unknown command: %q\nRun 'ddosctl help' for usage.", cmd)
	}

	if err != nil {
		fatalf("error: %v", err)
	}
}

// ─── Commands ─────────────────────────────────────────────────────────────────

func cmdStatus(c *apiClient) error {
	var m types.Metrics
	if err := c.get("/api/v1/metrics", &m); err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(m)
	}

	w := newTabWriter()
	fmt.Fprintln(w, "DDoS Mitigation Status")
	fmt.Fprintln(w, "──────────────────────────────────────────")
	fmt.Fprintf(w, "  Timestamp:\t%s\n", m.Timestamp.Format(time.RFC3339))
	fmt.Fprintf(w, "  PPS:\t%s pps\n", humanNum(m.PPS))
	fmt.Fprintf(w, "  BPS:\t%s\n", humanBits(m.BPS))
	fmt.Fprintf(w, "  Total Packets:\t%d\n", m.TotalPackets)
	fmt.Fprintf(w, "  Passed:\t%d\n", m.PassedPackets)
	fmt.Fprintf(w, "  Dropped:\t%d\n", m.DroppedPackets)
	fmt.Fprintf(w, "  Blocked IPs:\t%d\n", m.BlockedIPCount)
	fmt.Fprintln(w, "")
	fmt.Fprintf(w, "  SYN Floods:\t%d\n", m.SYNFloods)
	fmt.Fprintf(w, "  UDP Amplifications:\t%d\n", m.UDPAmplifications)
	fmt.Fprintf(w, "  ICMP Floods:\t%d\n", m.ICMPFloods)
	w.Flush()
	return nil
}

func cmdBlock(c *apiClient, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: block <ip> [reason: syn|udp|icmp]")
	}
	ip := args[0]
	reason := uint32(1)
	if len(args) >= 2 {
		switch args[1] {
		case "syn":
			reason = 1
		case "udp":
			reason = 2
		case "icmp":
			reason = 3
		default:
			return fmt.Errorf("reason must be syn, udp, or icmp (got %q)", args[1])
		}
	}
	var resp map[string]string
	if err := c.post("/api/v1/blocked", map[string]interface{}{"ip": ip, "reason": reason}, &resp); err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(resp)
	}
	greenf("✓ Blocked %s (reason: %s)\n", ip, types.ReasonString(reason))
	return nil
}

func cmdUnblock(c *apiClient, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: unblock <ip>")
	}
	var resp map[string]string
	if err := c.doDelete("/api/v1/blocked", map[string]string{"ip": args[0]}, &resp); err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(resp)
	}
	greenf("✓ Unblocked %s\n", args[0])
	return nil
}

func cmdBlocked(c *apiClient) error {
	var list []types.BlockedIP
	if err := c.get("/api/v1/blocked", &list); err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(list)
	}
	if len(list) == 0 {
		fmt.Println("No blocked IPs.")
		return nil
	}
	w := newTabWriter()
	fmt.Fprintln(w, "IP ADDRESS\tREASON\tBLOCKED AT")
	fmt.Fprintln(w, "──────────\t──────\t──────────")
	for _, b := range list {
		fmt.Fprintf(w, "%s\t%s\t%s\n",
			b.IP,
			b.Reason,
			b.BlockedAt.Format("2006-01-02 15:04:05"),
		)
	}
	w.Flush()
	fmt.Printf("\n%d IP(s) blocked\n", len(list))
	return nil
}

func cmdWhitelist(c *apiClient, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: whitelist <ip>")
	}
	var resp map[string]string
	if err := c.post("/api/v1/whitelist", map[string]string{"ip": args[0]}, &resp); err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(resp)
	}
	greenf("✓ Whitelisted %s\n", args[0])
	return nil
}

func cmdUnwhitelist(c *apiClient, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: unwhitelist <ip>")
	}
	var resp map[string]string
	if err := c.doDelete("/api/v1/whitelist", map[string]string{"ip": args[0]}, &resp); err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(resp)
	}
	greenf("✓ Removed %s from whitelist\n", args[0])
	return nil
}

func cmdAttackers(c *apiClient) error {
	var list []types.AttackingIP
	if err := c.get("/api/v1/attackers", &list); err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(list)
	}
	if len(list) == 0 {
		fmt.Println("No attacker data.")
		return nil
	}
	w := newTabWriter()
	fmt.Fprintln(w, "#\tIP ADDRESS\tTOTAL PKTS\tTOTAL BYTES\tSYN\tUDP\tICMP")
	fmt.Fprintln(w, "─\t──────────\t──────────\t───────────\t───\t───\t────")
	for i, a := range list {
		fmt.Fprintf(w, "%d\t%s\t%d\t%s\t%d\t%d\t%d\n",
			i+1,
			a.IP,
			a.TotalPackets,
			humanBytes(float64(a.TotalBytes)),
			a.SYNCount,
			a.UDPCount,
			a.ICMPCount,
		)
	}
	w.Flush()
	return nil
}

func cmdConfig(c *apiClient) error {
	var cfg types.Config
	if err := c.get("/api/v1/config", &cfg); err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(cfg)
	}
	w := newTabWriter()
	fmt.Fprintln(w, "XDP Configuration")
	fmt.Fprintln(w, "─────────────────────────────────────")
	enabled := "YES"
	if !cfg.Enabled {
		enabled = "NO (mitigation disabled)"
	}
	fmt.Fprintf(w, "  Mitigation Enabled:\t%s\n", enabled)
	fmt.Fprintf(w, "  SYN Rate Limit:\t%d pkt/s per IP\n", cfg.SYNRateLimit)
	fmt.Fprintf(w, "  UDP Rate Limit:\t%d pkt/s per IP\n", cfg.UDPRateLimit)
	fmt.Fprintf(w, "  ICMP Rate Limit:\t%d pkt/s per IP\n", cfg.ICMPRateLimit)
	w.Flush()
	return nil
}

func cmdSetConfig(c *apiClient, args []string) error {
	// Parse key=value pairs: syn=2000 udp=10000 icmp=200
	// First fetch current config as baseline
	var cfg types.Config
	if err := c.get("/api/v1/config", &cfg); err != nil {
		return fmt.Errorf("fetch current config: %w", err)
	}

	for _, arg := range args {
		kv := strings.SplitN(arg, "=", 2)
		if len(kv) != 2 {
			return fmt.Errorf("expected key=value, got %q", arg)
		}
		val, err := strconv.ParseUint(kv[1], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid value for %s: %v", kv[0], err)
		}
		switch kv[0] {
		case "syn":
			cfg.SYNRateLimit = val
		case "udp":
			cfg.UDPRateLimit = val
		case "icmp":
			cfg.ICMPRateLimit = val
		default:
			return fmt.Errorf("unknown key %q (valid: syn, udp, icmp)", kv[0])
		}
	}

	var resp map[string]interface{}
	if err := c.post("/api/v1/config", cfg, &resp); err != nil {
		return err
	}
	if *jsonOut {
		return printJSON(resp)
	}
	greenf("✓ Config updated\n")
	return cmdConfig(c)
}

func cmdSetEnabled(c *apiClient, enabled bool) error {
	var cfg types.Config
	if err := c.get("/api/v1/config", &cfg); err != nil {
		return fmt.Errorf("fetch config: %w", err)
	}
	cfg.Enabled = enabled
	var resp map[string]interface{}
	if err := c.post("/api/v1/config", cfg, &resp); err != nil {
		return err
	}
	if enabled {
		greenf("✓ Mitigation ENABLED\n")
	} else {
		warnf("⚠  Mitigation DISABLED — all traffic passes through\n")
	}
	return nil
}

func cmdWatch(c *apiClient) error {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	var prev types.Metrics

	for {
		select {
		case <-sigCh:
			fmt.Println("\nStopped.")
			return nil
		case <-ticker.C:
			var m types.Metrics
			if err := c.get("/api/v1/metrics", &m); err != nil {
				redf("error: %v\n", err)
				continue
			}
			// Clear line and overwrite
			fmt.Printf("\033[2J\033[H") // clear screen
			fmt.Printf("DDoS Watch  [%s]  Ctrl-C to stop\n\n",
				time.Now().Format("15:04:05"))

			fmt.Printf("  %-24s %12s\n", "Metric", "Value")
			fmt.Printf("  %-24s %12s\n", strings.Repeat("─", 24), strings.Repeat("─", 12))
			fmt.Printf("  %-24s %12s\n", "PPS", humanNum(m.PPS))
			fmt.Printf("  %-24s %12s\n", "Throughput", humanBits(m.BPS))
			fmt.Printf("  %-24s %12d\n", "Total Packets", m.TotalPackets)
			fmt.Printf("  %-24s %12d\n", "Dropped Packets", m.DroppedPackets)
			fmt.Printf("  %-24s %12d\n", "Passed Packets", m.PassedPackets)
			fmt.Printf("  %-24s %12d\n", "Blocked IPs", m.BlockedIPCount)
			fmt.Printf("  %-24s %12d\n", "SYN Floods", m.SYNFloods)
			fmt.Printf("  %-24s %12d\n", "UDP Amplifications", m.UDPAmplifications)
			fmt.Printf("  %-24s %12d\n", "ICMP Floods", m.ICMPFloods)

			// Delta since last poll
			if prev.TotalPackets > 0 {
				delta := m.DroppedPackets - prev.DroppedPackets
				fmt.Printf("\n  Drops this second: %d\n", delta)
			}
			prev = m

			// Top 5 attackers inline
			if len(m.TopAttackers) > 0 {
				fmt.Println("\n  Top Attackers:")
				for i, a := range m.TopAttackers {
					if i >= 5 {
						break
					}
					fmt.Printf("    %d. %-18s  pkts=%-10d  syn=%-8d  udp=%-8d\n",
						i+1, a.IP, a.TotalPackets, a.SYNCount, a.UDPCount)
				}
			}
		}
	}
}

// ─── HTTP client ──────────────────────────────────────────────────────────────

type apiClient struct {
	base string
	http *http.Client
}

func (c *apiClient) get(path string, out interface{}) error {
	resp, err := c.http.Get(c.base + path)
	if err != nil {
		return fmt.Errorf("GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		var e map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return fmt.Errorf("GET %s: HTTP %d: %s", path, resp.StatusCode, e["error"])
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *apiClient) post(path string, body interface{}, out interface{}) error {
	b, _ := json.Marshal(body)
	resp, err := c.http.Post(c.base+path, "application/json",
		strings.NewReader(string(b)))
	if err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		var e map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return fmt.Errorf("POST %s: HTTP %d: %s", path, resp.StatusCode, e["error"])
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *apiClient) doDelete(path string, body interface{}, out interface{}) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodDelete, c.base+path, strings.NewReader(string(b)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("DELETE %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		var e map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return fmt.Errorf("DELETE %s: HTTP %d: %s", path, resp.StatusCode, e["error"])
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// ─── Output helpers ───────────────────────────────────────────────────────────

func newTabWriter() *tabwriter.Writer {
	return tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
}

func printJSON(v interface{}) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func greenf(format string, args ...interface{}) {
	fmt.Printf("\033[32m"+format+"\033[0m", args...)
}

func warnf(format string, args ...interface{}) {
	fmt.Printf("\033[33m"+format+"\033[0m", args...)
}

func redf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "\033[31m"+format+"\033[0m", args...)
}

func fatalf(format string, args ...interface{}) {
	redf("Error: "+format+"\n", args...)
	os.Exit(1)
}

func humanNum(n float64) string {
	switch {
	case n >= 1e9:
		return fmt.Sprintf("%.2fG", n/1e9)
	case n >= 1e6:
		return fmt.Sprintf("%.2fM", n/1e6)
	case n >= 1e3:
		return fmt.Sprintf("%.2fK", n/1e3)
	default:
		return fmt.Sprintf("%.0f", n)
	}
}

func humanBits(bps float64) string {
	switch {
	case bps >= 1e12:
		return fmt.Sprintf("%.2f Tbps", bps/1e12)
	case bps >= 1e9:
		return fmt.Sprintf("%.2f Gbps", bps/1e9)
	case bps >= 1e6:
		return fmt.Sprintf("%.2f Mbps", bps/1e6)
	case bps >= 1e3:
		return fmt.Sprintf("%.2f Kbps", bps/1e3)
	default:
		return fmt.Sprintf("%.0f bps", bps)
	}
}

func humanBytes(b float64) string {
	switch {
	case b >= 1e12:
		return fmt.Sprintf("%.2f TB", b/1e12)
	case b >= 1e9:
		return fmt.Sprintf("%.2f GB", b/1e9)
	case b >= 1e6:
		return fmt.Sprintf("%.2f MB", b/1e6)
	case b >= 1e3:
		return fmt.Sprintf("%.2f KB", b/1e3)
	default:
		return fmt.Sprintf("%.0f B", b)
	}
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `ddosctl – DDoS Mitigation Platform CLI

Usage:
  ddosctl [--api URL] [--json] <command> [args]

Global Flags:
  --api URL    Control plane API URL (default: http://localhost:8080)
               Override with DDOS_API environment variable.
  --json       Output raw JSON instead of formatted tables.

Commands:
  status                        Show live traffic statistics
  watch                         Live-updating stats (refresh every 1s, Ctrl-C to stop)
  blocked                       List all currently blocked IPs
  block   <ip> [syn|udp|icmp]  Manually block an IP address
  unblock <ip>                  Remove an IP from the blocklist
  whitelist   <ip>              Add an IP to the bypass whitelist
  unwhitelist <ip>              Remove an IP from the whitelist
  attackers                     Show top 20 attacking source IPs
  config                        Show current XDP rate-limit configuration
  set-config [syn=N] [udp=N] [icmp=N]
                                Update rate limits (packets/sec per IP)
  enable                        Enable XDP packet filtering
  disable                       Disable XDP packet filtering (pass all traffic)
  help                          Show this help

Examples:
  ddosctl status
  ddosctl watch
  ddosctl block 1.2.3.4 syn
  ddosctl block 5.6.7.8 udp
  ddosctl unblock 1.2.3.4
  ddosctl attackers
  ddosctl set-config syn=2000 udp=10000 icmp=50
  ddosctl --api http://10.0.0.1:8080 blocked
  ddosctl --json status | jq .pps
`)
}
