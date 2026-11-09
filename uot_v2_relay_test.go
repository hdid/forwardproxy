package forwardproxy

import (
	"bytes"
	"net"
	"testing"
)

func TestSOCKS5UDPDatagramRoundTrip(t *testing.T) {
	want := uotAddress{Network: "udp", Host: "192.0.2.10", Port: 5353}
	payload := []byte{0x01, 0x02, 0x03, 0x04}
	packet, err := encodeSOCKS5Datagram(want, payload)
	if err != nil {
		t.Fatal(err)
	}
	got, gotPayload, err := decodeSOCKS5Datagram(packet)
	if err != nil {
		t.Fatal(err)
	}
	if got.Host != want.Host || got.Port != want.Port {
		t.Fatalf("destination = %s:%d, want %s:%d", got.Host, got.Port, want.Host, want.Port)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("payload = %v, want %v", gotPayload, payload)
	}
}

func TestSOCKS5UDPIPv6DatagramRoundTrip(t *testing.T) {
	want := uotAddress{Network: "udp", Host: "2001:db8::1", Port: 53}
	payload := []byte("dns")
	packet, err := encodeSOCKS5Datagram(want, payload)
	if err != nil {
		t.Fatal(err)
	}
	got, gotPayload, err := decodeSOCKS5Datagram(packet)
	if err != nil {
		t.Fatal(err)
	}
	if !net.ParseIP(got.Host).Equal(net.ParseIP(want.Host)) || got.Port != want.Port {
		t.Fatalf("destination = %s:%d, want %s:%d", got.Host, got.Port, want.Host, want.Port)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("payload = %q, want %q", gotPayload, payload)
	}
}

func TestUOTSessionLimits(t *testing.T) {
	remote := "192.0.2.1:12345"
	for i := 0; i < 64; i++ {
		if !acquireUOTSession(remote) {
			t.Fatalf("session %d unexpectedly rejected", i+1)
		}
	}
	if acquireUOTSession(remote) {
		t.Fatal("65th session unexpectedly accepted")
	}
	for i := 0; i < 64; i++ {
		releaseUOTSession(remote)
	}
	if !acquireUOTSession(remote) {
		t.Fatal("session was not released")
	}
	releaseUOTSession(remote)
}

func TestUDPPayloadLimits(t *testing.T) {
	if got := udpPayloadLimit(uotAddress{Port: 53}); got != 1232 {
		t.Fatalf("DNS limit = %d, want 1232", got)
	}
	if got := udpPayloadLimit(uotAddress{Port: 443}); got != 1200 {
		t.Fatalf("ordinary UDP limit = %d, want 1200", got)
	}
}
