// myaddr_test
package myaddr

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
)

type testMACConvertIncCase struct {
	addrStr        string
	step           int64
	expectedResult string
	shouldFail     bool
}

//strToByteSlice convert an hex columned string into byte slice,
//like "11:22:33" into []byte{11,22,33}
func strToByteSlice(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, ":", "")
	return hex.DecodeString(s)
}

func TestMACConvertion(t *testing.T) {
	testData := []testMACConvertIncCase{
		testMACConvertIncCase{
			addrStr: "11:22:33:44:55:66",
		},
		testMACConvertIncCase{
			addrStr:        "11:22:33:44:55:66",
			step:           1,
			expectedResult: "11:22:33:44:55:67",
		},
		testMACConvertIncCase{
			addrStr:        "11:22:33:44:55:ff",
			step:           1,
			expectedResult: "11:22:33:44:56:00",
		},
		testMACConvertIncCase{
			addrStr:        "10:00:00:00:00:00",
			step:           1,
			expectedResult: "10:00:00:00:00:01",
		},
		testMACConvertIncCase{
			addrStr:        "00:00:00:00:00:00",
			step:           1,
			expectedResult: "00:00:00:00:00:01",
		},
		testMACConvertIncCase{
			addrStr:        "00:00:00:00:00:01",
			step:           1,
			expectedResult: "00:00:00:00:00:02",
		},
		testMACConvertIncCase{
			addrStr: "00:00:00:00:00:00",
		},
		testMACConvertIncCase{
			addrStr:    "00:00:00:00:00:00",
			step:       -1,
			shouldFail: true,
		},
		testMACConvertIncCase{
			addrStr: "ff:FF:ff:ff:FF:ff",
		},
		testMACConvertIncCase{
			addrStr:    "ff:ff:ff:ff:FF:ff",
			step:       1,
			shouldFail: true,
		},
		testMACConvertIncCase{
			addrStr:    "ff:FF:ff:ff:FF:ff:ff:ff:ff",
			shouldFail: true,
		},
	}
	runTest := func(c testMACConvertIncCase) error {
		bslice, err := strToByteSlice(c.addrStr)
		if err != nil {
			return err
		}
		addr := net.HardwareAddr(bslice)
		convertedAddr, err := IncMACAddr(addr, big.NewInt(c.step))
		if err != nil {
			return err
		}
		if c.step == 0 {
			if addr.String() != convertedAddr.String() {
				return fmt.Errorf("converted back addr %v is different from expected result addr %v", convertedAddr, addr)
			}
		} else {
			if convertedAddr.String() != c.expectedResult {
				return fmt.Errorf("converted back addr %v is different from expected result addr %v", convertedAddr, c.expectedResult)
			}
		}

		return nil
	}
	for i, c := range testData {
		err := runTest(c)
		if err != nil {
			if c.shouldFail {
				t.Logf("expected case %d failed,%v ", i, err)
			} else {
				t.Fatal(err)
			}
		}
	}
}

type testConvertCase struct {
	addrStr    string
	ipv4       bool
	shouldFail bool
}

func TestConvertion(t *testing.T) {
	testData := []testConvertCase{
		testConvertCase{
			addrStr: "1.2.3.4",
			ipv4:    true,
		},
		testConvertCase{
			addrStr: "0.0.0.0",
			ipv4:    true,
		},
		testConvertCase{
			addrStr: "255.255.255.255",
			ipv4:    true,
		},
		testConvertCase{
			addrStr: "4.3.2.1",
			ipv4:    true,
		},
		testConvertCase{
			addrStr: "192.168.1.255",
			ipv4:    true,
		},
		testConvertCase{
			addrStr:    "4.3.2.1",
			ipv4:       false,
			shouldFail: true,
		},
		testConvertCase{
			addrStr: "2001:dead:beef::100",
			ipv4:    false,
		},
		testConvertCase{
			addrStr: "::",
			ipv4:    false,
		},
		testConvertCase{
			addrStr: "::3:4",
			ipv4:    false,
		},
		testConvertCase{
			addrStr: "::1",
			ipv4:    false,
		},
		testConvertCase{
			addrStr: "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF",
			ipv4:    false,
		},
		testConvertCase{
			addrStr:    "2001:dead:beef::100",
			ipv4:       true,
			shouldFail: true,
		},
	}
	runTest := func(c testConvertCase) error {
		addr := net.ParseIP(c.addrStr)
		n := AddrtoBig(addr)
		convertedAddr, err := BigtoAddr(n, c.ipv4)
		if err != nil {
			return err
		}
		if !addr.Equal(convertedAddr) {
			return fmt.Errorf("converted back addr %v is different from original addr %v", convertedAddr, addr)
		}
		return nil
	}
	for i, c := range testData {
		err := runTest(c)
		if err != nil {
			if c.shouldFail {
				t.Logf("expected case %d failed,%v ", i, err)
			} else {
				t.Fatal(err)
			}
		}
	}
}

type testIncCase struct {
	addrStr      string
	step         int64
	expectedAddr string
	shouldFail   bool
}

func TestIncAddr(t *testing.T) {
	testData := []testIncCase{
		testIncCase{
			addrStr:      "1.1.1.1",
			step:         1,
			expectedAddr: "1.1.1.2",
		},
		testIncCase{
			addrStr:      "1.1.1.255",
			step:         1,
			expectedAddr: "1.1.2.0",
		},
		testIncCase{
			addrStr:      "192.168.10.255",
			step:         10,
			expectedAddr: "192.168.11.9",
		},
		testIncCase{
			addrStr:    "0.0.0.1",
			step:       -10,
			shouldFail: true,
		},
		testIncCase{
			addrStr:    "255.255.255.255",
			step:       10,
			shouldFail: true,
		},
		testIncCase{
			addrStr:      "::3:4",
			step:         1,
			expectedAddr: "::3:5",
		},
		testIncCase{
			addrStr:      "::4",
			step:         1,
			expectedAddr: "::5",
		},
	}
	runTest := func(c testIncCase) error {
		addr := net.ParseIP(c.addrStr)
		raddr, err := IncAddr(addr, big.NewInt(c.step))
		if err != nil {
			return err
		}
		if !raddr.Equal(net.ParseIP(c.expectedAddr)) {
			return fmt.Errorf("result addr %v is different from expected %v", raddr, c.expectedAddr)
		}
		return nil
	}

	for i, c := range testData {
		err := runTest(c)
		if err != nil {
			if c.shouldFail {
				t.Logf("expected case %d failed,%v ", i, err)
			} else {
				t.Fatal(err)
			}
		}
	}
}

type testGenAddrWithPrefixCase struct {
	prefixStr    string
	hostn        int64
	expectedAddr string
	shouldFail   bool
}

func TestGenAddrWithPrefix(t *testing.T) {
	testdata := []testGenAddrWithPrefixCase{
		testGenAddrWithPrefixCase{
			prefixStr:    "192.168.1.200/24",
			hostn:        100,
			expectedAddr: "192.168.1.100",
		},
		testGenAddrWithPrefixCase{
			prefixStr:    "192.168.1.100/24",
			hostn:        256,
			expectedAddr: "192.168.1.100",
			shouldFail:   true,
		},
		testGenAddrWithPrefixCase{
			prefixStr:    "2001:dead:beef::/64",
			hostn:        100000,
			expectedAddr: "2001:dead:beef::1:86a0",
		},
		testGenAddrWithPrefixCase{
			prefixStr:  "2001:dead:beef::/64",
			hostn:      -1,
			shouldFail: true,
		},
	}
	runTest := func(c testGenAddrWithPrefixCase) error {
		_, prefix, err := net.ParseCIDR(c.prefixStr)
		if err != nil {
			return fmt.Errorf("failed to parse test case prefix,%v", err)
		}
		rip, err := GenAddrWithPrefix(prefix, big.NewInt(c.hostn))
		if err != nil {
			return fmt.Errorf("failed to generate address,%v", err)
		}
		if !rip.Equal(net.ParseIP(c.expectedAddr)) {
			return fmt.Errorf("result addr %v is different from expected addr %v", rip, c.expectedAddr)
		}
		return nil

	}
	for i, c := range testdata {
		err := runTest(c)
		if err != nil {
			if c.shouldFail {
				t.Logf("expected case %d failed,%v ", i, err)
			} else {
				t.Fatal(err)
			}
		}
	}
}

type testGenConnectionCase struct {
	prefixStr    string
	ip           net.IP
	port         int
	expectedAddr string
	shouldFail   bool
}

func TestGenConnectionAddStr(t *testing.T) {
	testData := []testGenConnectionCase{
		testGenConnectionCase{
			prefixStr:    "http://",
			ip:           net.ParseIP("192.168.1.1"),
			port:         8043,
			expectedAddr: "http://192.168.1.1:8043",
		},
		testGenConnectionCase{
			prefixStr:    "http://",
			ip:           net.ParseIP("2001:dead::1"),
			port:         8043,
			expectedAddr: "http://[2001:dead::1]:8043",
		},
	}
	runTest := func(c testGenConnectionCase) error {
		rstr := GenConnectionAddrStr(c.prefixStr, c.ip, c.port)
		if rstr != c.expectedAddr {
			return fmt.Errorf("result %v is different from expected %v", rstr, c.expectedAddr)
		}
		return nil
	}
	for i, c := range testData {
		err := runTest(c)
		if err != nil {
			if c.shouldFail {
				t.Logf("expected case %d failed,%v ", i, err)
			} else {
				t.Fatal(err)
			}
		}
	}
}
