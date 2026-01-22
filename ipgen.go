package main

import (
	"fmt"
	"net"
)

// Common DNS server IP octets (last byte)
// Expanded list based on actual Iranian DNS servers found
var commonDNSOctets = []int{
	1, 2, 3, 5, 6, 10, 12, 14, 15, 17, 20, 21, 22, 25, 26, 33, 34, 35, 37, 38,
	40, 41, 42, 43, 44, 50, 51, 53, 60, 62, 65, 66, 69, 73, 80, 81, 85, 88, 89,
	100, 101, 102, 104, 105, 106, 108, 109, 112, 113, 114, 115, 116, 120, 122,
	126, 127, 128, 130, 131, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142,
	143, 144, 145, 148, 151, 154, 155, 157, 158, 159, 161, 163, 164, 174, 176,
	180, 182, 184, 186, 187, 190, 194, 196, 200, 201, 202, 206, 210, 214, 215,
	220, 221, 222, 225, 226, 229, 232, 235, 236, 239, 243, 244, 253, 254,
}

// ExpandCIDR generates IPs from a CIDR range
// For /16: samples common DNS IPs in each /24 subnet (2048 IPs per /16)
// For /24: all 254 IPs
// For others: samples common DNS IPs
func ExpandCIDR(cidr string) <-chan string {
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

		switch ones {
		case 16:
			// /16 - sample common DNS IPs in each /24 (256 * 8 = 2048 IPs)
			for o3 := 0; o3 <= 255; o3++ {
				for _, o4 := range commonDNSOctets {
					out <- fmt.Sprintf("%d.%d.%d.%d", base[0], base[1], o3, o4)
				}
			}
		case 24:
			// /24 - all usable IPs (1-254)
			for o4 := 1; o4 <= 254; o4++ {
				out <- fmt.Sprintf("%d.%d.%d.%d", base[0], base[1], base[2], o4)
			}
		default:
			// Other prefixes - sample common DNS IPs in each /24 within range
			// Calculate number of /24s in this range
			numHosts := uint32(1) << (32 - ones)
			baseInt := ipToUint32(base)

			for i := uint32(0); i < numHosts; i += 256 {
				subnetBase := uint32ToIP(baseInt + i)
				for _, o4 := range commonDNSOctets {
					out <- fmt.Sprintf("%d.%d.%d.%d", subnetBase[0], subnetBase[1], subnetBase[2], o4)
				}
			}
		}
	}()

	return out
}

// ExpandRanges expands multiple CIDR ranges and merges into single channel
func ExpandRanges(ranges []string) <-chan string {
	out := make(chan string, 10000)

	go func() {
		defer close(out)
		for _, cidr := range ranges {
			for ip := range ExpandCIDR(cidr) {
				out <- ip
			}
		}
	}()

	return out
}

// IPsFromList converts a slice of IPs to a channel
func IPsFromList(ips []string) <-chan string {
	out := make(chan string, len(ips))

	go func() {
		defer close(out)
		for _, ip := range ips {
			out <- ip
		}
	}()

	return out
}

// CountIPs estimates total IPs that will be generated
func CountIPs(ranges []string) int {
	total := 0
	for _, cidr := range ranges {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}

		ones, _ := ipnet.Mask.Size()
		switch ones {
		case 16:
			total += 256 * len(commonDNSOctets) // 2048
		case 24:
			total += 254
		default:
			numHosts := 1 << (32 - ones)
			num24s := numHosts / 256
			if num24s == 0 {
				num24s = 1
			}
			total += num24s * len(commonDNSOctets)
		}
	}
	return total
}

func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

func uint32ToIP(n uint32) net.IP {
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}
