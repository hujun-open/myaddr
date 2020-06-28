// myaddr
package myaddr

import (
	"fmt"
	"math/big"
	"net"
)

//AddrtoBig convert IP address to *big.Int
func AddrtoBig(addr net.IP) *big.Int {
	r := new(big.Int)
	if addr.To4() != nil {
		r.SetBytes(addr.To4()[:4])
	} else {
		r.SetBytes(addr.To16()[:16])

	}
	return r
}

//BigtoAddr convert n to IPv4 address if ipv4 is true, IPv6 address otherwise
func BigtoAddr(n *big.Int, ipv4 bool) (net.IP, error) {
	buf := n.Bytes()
	var alen = 4
	var delta int
	if ipv4 {
		delta = 4 - len(buf)
		if delta < 0 {
			//this should be an IPv6 address
			return nil, fmt.Errorf("%v is too big for an IPv4 address", n)
		}
	} else {
		delta = 16 - len(buf)
		alen = 16
	}
	rbuf := make([]byte, alen)
	copy(rbuf[delta:], buf)
	return rbuf, nil
}

const (
	MaxIPv4AddrN   = 4294967295
	MaxIPv6AddrStr = "340282366920938463463374607431768211455"
)

//IncAddr increase addr by step (could be negative), return the result
func IncAddr(addr net.IP, step *big.Int) (net.IP, error) {

	rn := big.NewInt(0).Add(AddrtoBig(addr), step)
	if rn.Cmp(big.NewInt(0)) == -1 {
		return nil, fmt.Errorf("%v and step %d result in negative result", addr, step)
	}
	if addr.To4() != nil {
		//ipv4
		if rn.Cmp(big.NewInt(MaxIPv4AddrN)) == 1 {
			return nil, fmt.Errorf("%v and step %d result exceeds 255.255.255.255", addr, step)
		}
		return BigtoAddr(rn, true)
	} else {
		//ipv6
		maxv6addr, _ := big.NewInt(0).SetString(MaxIPv6AddrStr, 0)
		if rn.Cmp(maxv6addr) == 1 {
			return nil, fmt.Errorf("%v and step %d result exceeds FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF", addr, step)
		}
		return BigtoAddr(rn, false)

	}
}

//GenAddrWithPrefix geneate an address = prefix + hostn.
//hostn must>=0
func GenAddrWithPrefix(prefix *net.IPNet, hostn *big.Int) (net.IP, error) {
	if hostn.Cmp(big.NewInt(0)) == -1 {
		return nil, fmt.Errorf("%v is negative", hostn)
	}
	maskbits, totalmaskbits := prefix.Mask.Size()
	deltan := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(int64(totalmaskbits-maskbits)), big.NewInt(0))
	if hostn.Cmp(deltan) >= 0 {
		return nil, fmt.Errorf("%v exceeds max allowed host value for prefix %v", hostn, prefix)
	}
	return IncAddr(prefix.IP, hostn)
}

//GenConnectionAddrStr return a string with following format:
//IPv4: <prefix><ip>:<port>
//IPv6: <prefix>[<ip>]:<port>
func GenConnectionAddrStr(prefix string, ip net.IP, port int) string {
	if ip.To4() != nil {
		return fmt.Sprintf("%v%v:%v", prefix, ip, port)
	} else {
		return fmt.Sprintf("%v[%v]:%v", prefix, ip, port)
	}
}
