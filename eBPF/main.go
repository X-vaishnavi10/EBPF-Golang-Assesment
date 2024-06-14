package main

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
)

const (
	xdpProgPath = "drop.o"
	defaultPort = 4040
)

func main() {
	if len(os.Args) < 2 {
		fmt.Printf("Using default port %d\n", defaultPort)
	}

	port := defaultPort
	if len(os.Args) > 1 {
		_, err := fmt.Sscanf(os.Args[1], "%d", &port)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid port: %v\n", err)
			os.Exit(1)
		}
	}

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to set rlimit: %v\n", err)
		os.Exit(1)
	}

	spec, err := ebpf.LoadCollectionSpec(xdpProgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load collection spec: %v\n", err)
		os.Exit(1)
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create collection: %v\n", err)
		os.Exit(1)
	}
	defer coll.Close()

	dropPortMap := coll.Maps["drop_port"]
	key := uint32(0)
	value := uint32(port)
	if err := dropPortMap.Put(key, value); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to update map: %v\n", err)
		os.Exit(1)
	}

	iface, err := netlink.LinkByName("eth0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get interface: %v\n", err)
		os.Exit(1)
	}

	prog := coll.Programs["drop_packet"]
	if prog == nil {
		fmt.Fprintf(os.Stderr, "Failed to find program: %v\n", err)
		os.Exit(1)
	}

	link, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: iface.Attrs().Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach XDP program: %v\n", err)
		os.Exit(1)
	}
	defer link.Close()

	fmt.Printf("eBPF program loaded and attached. Dropping packets on port %d.\n", port)

	// Keep the program running
	select {}
}
