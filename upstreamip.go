package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"

	"codeberg.org/emersion/go-scfg"
)

// UpstreamIP is the source address soju uses for one user's upstream
// connections in one of the upstream-user-ip ranges.
type UpstreamIP struct {
	IP         string `json:"ip"`
	Range      string `json:"range"`
	Configured bool   `json:"configured"` // assigned to an interface we can see
	Active     bool   `json:"active"`     // an established TCP connection uses it
	Error      string `json:"error,omitempty"`
}

// upstreamRanges reads the upstream-user-ip ranges from the config soju is
// actually running with.
func upstreamRanges(configPath string) ([]*net.IPNet, error) {
	block, err := scfg.Load(configPath)
	if err != nil {
		return nil, err
	}
	var ranges []*net.IPNet
	for _, d := range block.GetAll("upstream-user-ip") {
		for _, p := range d.Params {
			_, n, err := net.ParseCIDR(p)
			if err != nil {
				return nil, fmt.Errorf("upstream-user-ip %q: %v", p, err)
			}
			ranges = append(ranges, n)
		}
	}
	return ranges, nil
}

// userUpstreamIP mirrors soju's user.localTCPAddr: base address + (ID + 1).
func userUpstreamIP(n *net.IPNet, id int64) (net.IP, error) {
	var v big.Int
	v.SetBytes(n.IP)
	v.Add(&v, big.NewInt(id+1))
	b := v.Bytes()
	if len(b) > len(n.IP) {
		return nil, fmt.Errorf("range %v too small", n)
	}
	ip := make(net.IP, len(n.IP))
	copy(ip[len(ip)-len(b):], b)
	if !n.Contains(ip) {
		return nil, fmt.Errorf("range %v too small for user ID %d", n, id)
	}
	return ip, nil
}

// localIPs returns the addresses assigned to the interfaces visible to this
// process. With hostNetwork that's the node's interfaces, which are the
// ones soju can bind.
func localIPs() map[string]bool {
	out := map[string]bool{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			out[n.IP.String()] = true
		}
	}
	return out
}

// establishedSourceIPs lists the local addresses of established TCP
// connections in our network namespace, from /proc/net/tcp{,6}.
func establishedSourceIPs() map[string]bool {
	out := map[string]bool{}
	for _, file := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		f, err := os.Open(file)
		if err != nil {
			continue
		}
		parseProcNetTCP(bufio.NewScanner(f), out)
		f.Close()
	}
	return out
}

const tcpEstablished = "01"

func parseProcNetTCP(sc *bufio.Scanner, out map[string]bool) {
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 || fields[3] != tcpEstablished {
			continue
		}
		addr, _, ok := strings.Cut(fields[1], ":")
		if !ok {
			continue
		}
		if ip := parseProcIP(addr); ip != nil {
			out[ip.String()] = true
		}
	}
}

// parseProcIP decodes /proc/net addresses: 32-bit words in host (little
// endian) byte order.
func parseProcIP(s string) net.IP {
	b, err := hex.DecodeString(s)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return nil
	}
	ip := make(net.IP, len(b))
	for i := 0; i < len(b); i += 4 {
		ip[i], ip[i+1], ip[i+2], ip[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	return ip
}

// upstreamIPsByUser computes each user's source addresses and their state.
func upstreamIPsByUser(configPath string, ids []int64) (map[int64][]UpstreamIP, error) {
	ranges, err := upstreamRanges(configPath)
	if err != nil || len(ranges) == 0 {
		return nil, err
	}
	local, active := localIPs(), establishedSourceIPs()
	out := map[int64][]UpstreamIP{}
	for _, id := range ids {
		for _, n := range ranges {
			u := UpstreamIP{Range: n.String()}
			ip, err := userUpstreamIP(n, id)
			if err != nil {
				u.Error = err.Error()
			} else {
				u.IP = ip.String()
				u.Configured = local[u.IP]
				u.Active = active[u.IP]
			}
			out[id] = append(out[id], u)
		}
	}
	return out, nil
}
