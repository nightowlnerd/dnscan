package main

import (
	"fmt"
	"net"
)

// Sampling strategies for different modes
var (
	// fast: common gateway/DNS positions
	fastOctets = []int{1, 53, 254}

	// medium: expanded common positions
	mediumOctets = []int{1, 2, 10, 53, 100, 200, 254}

	// all: every usable IP (generated dynamically)
)

// ExpandRangesWithMode expands CIDR ranges using the specified sampling mode
func ExpandRangesWithMode(ranges []string, mode string) <-chan string {
	out := make(chan string, 10000)

	go func() {
		defer close(out)
		for _, cidr := range ranges {
			for ip := range expandCIDRWithMode(cidr, mode) {
				out <- ip
			}
		}
	}()

	return out
}

// expandCIDRWithMode generates IPs from a CIDR range based on mode
func expandCIDRWithMode(cidr string, mode string) <-chan string {
	out := make(chan string, 1000)

	go func() {
		defer close(out)

		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			return
		}

		ones, bits := ipnet.Mask.Size()
		if bits != 32 {
			return // Only IPv4
		}

		base := ipnet.IP.To4()
		if base == nil {
			return
		}

		// Get octets to sample based on mode
		var octets []int
		switch mode {
		case "fast":
			octets = fastOctets
		case "medium":
			octets = mediumOctets
		case "all":
			// Generate all 1-254
			octets = make([]int, 254)
			for i := 1; i <= 254; i++ {
				octets[i-1] = i
			}
		default:
			octets = fastOctets
		}

		// Expand based on prefix length
		numHosts := uint32(1) << (32 - ones)
		baseInt := ipToUint32(base)

		// Iterate through each /24 in the range
		for i := uint32(0); i < numHosts; i += 256 {
			subnetBase := uint32ToIP(baseInt + i)
			for _, o4 := range octets {
				out <- fmt.Sprintf("%d.%d.%d.%d", subnetBase[0], subnetBase[1], subnetBase[2], o4)
			}
		}
	}()

	return out
}


// CountIPsWithMode estimates total IPs based on ranges and mode
func CountIPsWithMode(ranges []string, mode string) int {
	var octetsPerSubnet int
	switch mode {
	case "fast":
		octetsPerSubnet = len(fastOctets)
	case "medium":
		octetsPerSubnet = len(mediumOctets)
	case "all":
		octetsPerSubnet = 254
	default:
		octetsPerSubnet = len(fastOctets)
	}

	total := 0
	for _, cidr := range ranges {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}

		ones, _ := ipnet.Mask.Size()
		numHosts := 1 << (32 - ones)
		num24s := numHosts / 256
		if num24s == 0 {
			num24s = 1
		}
		total += num24s * octetsPerSubnet
	}
	return total
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n)).To4()
}
