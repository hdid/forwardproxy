package forwardproxy

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestUOTV2RequestHeader(t *testing.T) {
	// isConnect=1, SOCKS5 IPv4 192.0.2.1:53
	wire, _ := hex.DecodeString("0101c00002010035")
	connect, dst, err := readUOTRequest(bytes.NewReader(wire))
	if err != nil {
		t.Fatal(err)
	}
	if !connect || dst.Host != "192.0.2.1" || dst.Port != 53 {
		t.Fatalf("unexpected request: connect=%v dst=%+v", connect, dst)
	}
}

func TestUOTV2ConnectFrame(t *testing.T) {
	wire, _ := hex.DecodeString("000568656c6c6f")
	dst, payload, err := readUOTFrame(bytes.NewReader(wire), true, uotAddress{Host: "192.0.2.1", Port: 53}, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if dst.Host != "192.0.2.1" || string(payload) != "hello" {
		t.Fatalf("unexpected frame: %+v %q", dst, payload)
	}
}

func TestUOTV2NonConnectFrameUsesUOTAddressTypes(t *testing.T) {
	// UoT address parser: 0x02=FQDN, then length, name, port, payload length, data.
	wire, _ := hex.DecodeString("020b6578616d706c652e636f6d00350003646e73")
	dst, payload, err := readUOTFrame(bytes.NewReader(wire), false, uotAddress{}, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if dst.Host != "example.com" || dst.Port != 53 || string(payload) != "dns" {
		t.Fatalf("unexpected frame: %+v %q", dst, payload)
	}
}

func TestUOTV2RejectsOversizeAndInvalidMode(t *testing.T) {
	if _, _, err := readUOTFrame(bytes.NewReader([]byte{0, 0, 1, 'x'}), true, uotAddress{}, 0); err == nil {
		t.Fatal("expected invalid payload length")
	}
	if _, _, err := readUOTRequest(bytes.NewReader([]byte{2})); err == nil {
		t.Fatal("expected invalid request mode")
	}
}
