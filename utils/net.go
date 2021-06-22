package utils

import "net"

// derived from: https://gist.github.com/kotakanbe/d3059af990252ba89a82
func NextIP(ip net.IP) net.IP {
	nip := net.IP(make(net.IP, len(ip)))
	copy(nip, ip)
	for j := len(nip) - 1; j >= 0; j-- {
		nip[j]++
		if nip[j] > 0 {
			break
		}
	}
	return nip
}

// derived from: https://gist.github.com/kotakanbe/d3059af990252ba89a82
func PrevIP(ip net.IP) net.IP {
	nip := net.IP(make(net.IP, len(ip)))
	copy(nip, ip)
	for j := len(nip) - 1; j >= 0; j-- {
		nip[j]--
		if nip[j] < 255 {
			break
		}
	}
	return nip
}
