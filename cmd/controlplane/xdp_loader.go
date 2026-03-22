package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const (
	bpfPinPath   = "/sys/fs/bpf/ddos"
	xdpObjPath   = "/usr/local/lib/ddos/xdp_main.o"
	xdpProgName  = "xdp_main"
)

// XDPObjects holds loaded BPF objects (program + maps).
type XDPObjects struct {
	Program      *ebpf.Program
	IPStatsMap   *ebpf.Map
	BlockedIPs   *ebpf.Map
	GlobalStats  *ebpf.Map
	WhitelistMap *ebpf.Map
	ConfigMap    *ebpf.Map
	link         link.Link
}

// LoadXDP loads the XDP BPF object from disk, pins maps, and attaches to iface.
func LoadXDP(iface string, replace bool) (*XDPObjects, error) {
	// Ensure BPF filesystem is mounted
	if err := ensureBPFFS(); err != nil {
		return nil, fmt.Errorf("bpffs: %w", err)
	}

	// Ensure pin directory exists
	if err := os.MkdirAll(bpfPinPath, 0755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", bpfPinPath, err)
	}

	spec, err := ebpf.LoadCollectionSpec(xdpObjPath)
	if err != nil {
		return nil, fmt.Errorf("load BPF obj %s: %w", xdpObjPath, err)
	}

	// Configure pin paths for each map
	mapPins := map[string]string{
		"ip_stats_map":    filepath.Join(bpfPinPath, "ip_stats_map"),
		"blocked_ips":     filepath.Join(bpfPinPath, "blocked_ips"),
		"global_stats_map": filepath.Join(bpfPinPath, "global_stats_map"),
		"whitelist_map":   filepath.Join(bpfPinPath, "whitelist_map"),
		"config_map":      filepath.Join(bpfPinPath, "config_map"),
	}

	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: bpfPinPath,
		},
	}

	// If not replacing, try to reuse existing pinned maps
	if !replace {
		for name, pinPath := range mapPins {
			if _, err := os.Stat(pinPath); err == nil {
				log.Printf("reusing pinned map: %s", name)
			}
		}
	} else {
		// Remove old pins
		for _, pinPath := range mapPins {
			_ = os.Remove(pinPath)
		}
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, *opts)
	if err != nil {
		return nil, fmt.Errorf("create collection: %w", err)
	}

	prog := coll.Programs[xdpProgName]
	if prog == nil {
		coll.Close()
		return nil, fmt.Errorf("program %q not found in BPF object", xdpProgName)
	}

	// Attach XDP to interface
	ifc, err := net.InterfaceByName(iface)
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("interface %q: %w", iface, err)
	}

	// Try native (driver) mode first; fall back to generic SKB mode.
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifc.Index,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		log.Printf("native XDP unavailable on %s (%v), falling back to generic mode", iface, err)
		xdpLink, err = link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: ifc.Index,
			Flags:     link.XDPGenericMode,
		})
		if err != nil {
			coll.Close()
			return nil, fmt.Errorf("attach XDP (generic) to %s: %w", iface, err)
		}
		log.Printf("XDP attached in generic mode on %s (index %d)", iface, ifc.Index)
	} else {
		log.Printf("XDP attached in native mode on %s (index %d)", iface, ifc.Index)
	}

	objs := &XDPObjects{
		Program:      prog,
		IPStatsMap:   coll.Maps["ip_stats_map"],
		BlockedIPs:   coll.Maps["blocked_ips"],
		GlobalStats:  coll.Maps["global_stats_map"],
		WhitelistMap: coll.Maps["whitelist_map"],
		ConfigMap:    coll.Maps["config_map"],
		link:         xdpLink,
	}

	// Initialize default config
	if err := initDefaultConfig(objs); err != nil {
		log.Printf("warning: could not initialize default config: %v", err)
	}

	return objs, nil
}

// initDefaultConfig writes default rate-limit thresholds to the config map.
func initDefaultConfig(objs *XDPObjects) error {
	defaults := map[uint32]uint64{
		0: 1000,  // CFG_SYN_RATE
		1: 5000,  // CFG_UDP_RATE
		2: 100,   // CFG_ICMP_RATE
		3: 1,     // CFG_ENABLED
	}
	for k, v := range defaults {
		if err := objs.ConfigMap.Put(k, v); err != nil {
			return fmt.Errorf("config key %d: %w", k, err)
		}
	}
	log.Println("XDP config map initialized with defaults")
	return nil
}

// DetachXDP removes the XDP program from the interface and cleans up.
func (x *XDPObjects) DetachXDP() error {
	if x.link != nil {
		if err := x.link.Close(); err != nil {
			return fmt.Errorf("close xdp link: %w", err)
		}
	}
	log.Println("XDP detached successfully")
	return nil
}

// UnpinMaps removes all pinned BPF objects from the filesystem.
func UnpinMaps() error {
	entries, err := os.ReadDir(bpfPinPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		path := filepath.Join(bpfPinPath, e.Name())
		if err := os.Remove(path); err != nil {
			log.Printf("warning: remove pin %s: %v", path, err)
		}
	}
	return os.Remove(bpfPinPath)
}

// ensureBPFFS mounts the BPF filesystem if not already mounted.
func ensureBPFFS() error {
	const bpfFSPath = "/sys/fs/bpf"
	const bpfFSType = "bpf"

	// Check if already mounted
	data, err := os.ReadFile("/proc/mounts")
	if err == nil {
		for _, line := range splitLines(string(data)) {
			if len(line) > 0 {
				fields := splitFields(line)
				if len(fields) >= 3 && fields[1] == bpfFSPath && fields[2] == bpfFSType {
					return nil // already mounted
				}
			}
		}
	}

	// Mount bpffs
	if err := unix.Mount(bpfFSType, bpfFSPath, bpfFSType, 0, ""); err != nil {
		return fmt.Errorf("mount bpffs: %w", err)
	}
	log.Println("BPF filesystem mounted at /sys/fs/bpf")
	return nil
}

// WaitForShutdown blocks until the xdp loader receives a stop signal.
// Called from main after setup is complete.
func WaitForShutdown(stop <-chan struct{}, objs *XDPObjects) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			log.Println("shutdown: detaching XDP...")
			if err := objs.DetachXDP(); err != nil {
				log.Printf("detach error: %v", err)
			}
			return
		case <-ticker.C:
			log.Println("XDP loader heartbeat: running")
		}
	}
}

// ─── tiny string helpers (avoid importing strings to keep deps lean) ─────────

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func splitFields(s string) []string {
	var out []string
	start := -1
	for i := 0; i < len(s); i++ {
		if s[i] != ' ' && s[i] != '\t' {
			if start == -1 {
				start = i
			}
		} else {
			if start != -1 {
				out = append(out, s[start:i])
				start = -1
			}
		}
	}
	if start != -1 {
		out = append(out, s[start:])
	}
	return out
}
