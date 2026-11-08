// Copyright 2026
// UoT v2 framing primitives. This file deliberately contains no routing policy;
// callers must authenticate and authorize destinations before relaying packets.
package forwardproxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

const uotV2MagicAddress = "sp.v2.udp-over-tcp.arpa"

var errUOTMalformed = errors.New("malformed UoT v2 frame")

type uotAddress struct {
	Network string
	Host    string
	Port    uint16
}

// readSOCKSAddress reads the UoT v2 request address, which uses SOCKS5 ATYP.
func readSOCKSAddress(r io.Reader) (uotAddress, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return uotAddress{}, err
	}
	switch atyp[0] {
	case 0x01:
		var b [6]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return uotAddress{}, err
		}
		return uotAddress{Network: "udp", Host: net.IP(b[:4]).String(), Port: binary.BigEndian.Uint16(b[4:])}, nil
	case 0x04:
		var b [18]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return uotAddress{}, err
		}
		return uotAddress{Network: "udp", Host: net.IP(b[:16]).String(), Port: binary.BigEndian.Uint16(b[16:])}, nil
	case 0x03:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return uotAddress{}, err
		}
		if n[0] == 0 {
			return uotAddress{}, errUOTMalformed
		}
		b := make([]byte, int(n[0])+2)
		if _, err := io.ReadFull(r, b); err != nil {
			return uotAddress{}, err
		}
		return uotAddress{Network: "udp", Host: string(b[:len(b)-2]), Port: binary.BigEndian.Uint16(b[len(b)-2:])}, nil
	default:
		return uotAddress{}, fmt.Errorf("%w: unsupported SOCKS ATYP 0x%02x", errUOTMalformed, atyp[0])
	}
}

// readPacketAddress reads the per-datagram address used by UoT v2 non-connect
// mode. sing/common/uot uses ATYP 0x00/0x01/0x02 (not SOCKS5's 0x01/0x04/0x03).
func readPacketAddress(r io.Reader) (uotAddress, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return uotAddress{}, err
	}
	switch atyp[0] {
	case 0x00: // IPv4
		var b [6]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return uotAddress{}, err
		}
		return uotAddress{Network: "udp", Host: net.IP(b[:4]).String(), Port: binary.BigEndian.Uint16(b[4:])}, nil
	case 0x01: // IPv6
		var b [18]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return uotAddress{}, err
		}
		return uotAddress{Network: "udp", Host: net.IP(b[:16]).String(), Port: binary.BigEndian.Uint16(b[16:])}, nil
	case 0x02: // FQDN
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return uotAddress{}, err
		}
		if n[0] == 0 {
			return uotAddress{}, errUOTMalformed
		}
		b := make([]byte, int(n[0])+2)
		if _, err := io.ReadFull(r, b); err != nil {
			return uotAddress{}, err
		}
		return uotAddress{Network: "udp", Host: string(b[:len(b)-2]), Port: binary.BigEndian.Uint16(b[len(b)-2:])}, nil
	default:
		return uotAddress{}, fmt.Errorf("%w: unsupported packet ATYP 0x%02x", errUOTMalformed, atyp[0])
	}
}

func writeFull(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

func writeSOCKSAddress(w io.Writer, a uotAddress) error {
	ip := net.ParseIP(a.Host)
	switch {
	case ip != nil && ip.To4() != nil:
		var b [7]byte
		b[0] = 0x01
		copy(b[1:5], ip.To4())
		binary.BigEndian.PutUint16(b[5:], a.Port)
		_, err := w.Write(b[:])
		return err
	case ip != nil:
		var b [19]byte
		b[0] = 0x04
		copy(b[1:17], ip.To16())
		binary.BigEndian.PutUint16(b[17:], a.Port)
		_, err := w.Write(b[:])
		return err
	default:
		if len(a.Host) == 0 || len(a.Host) > 255 {
			return errUOTMalformed
		}
		b := make([]byte, 1+1+len(a.Host)+2)
		b[0], b[1] = 0x03, byte(len(a.Host))
		copy(b[2:], a.Host)
		binary.BigEndian.PutUint16(b[len(b)-2:], a.Port)
		_, err := w.Write(b)
		return err
	}
}

func writePacketAddress(w io.Writer, a uotAddress) error {
	ip := net.ParseIP(a.Host)
	switch {
	case ip != nil && ip.To4() != nil:
		var b [7]byte
		b[0] = 0x00
		copy(b[1:5], ip.To4())
		binary.BigEndian.PutUint16(b[5:], a.Port)
		_, err := w.Write(b[:])
		return err
	case ip != nil:
		var b [19]byte
		b[0] = 0x01
		copy(b[1:17], ip.To16())
		binary.BigEndian.PutUint16(b[17:], a.Port)
		_, err := w.Write(b[:])
		return err
	default:
		if len(a.Host) == 0 || len(a.Host) > 255 {
			return errUOTMalformed
		}
		b := make([]byte, 1+1+len(a.Host)+2)
		b[0], b[1] = 0x02, byte(len(a.Host))
		copy(b[2:], a.Host)
		binary.BigEndian.PutUint16(b[len(b)-2:], a.Port)
		_, err := w.Write(b)
		return err
	}
}

// readUOTRequest reads isConnect followed by a SOCKS5-formatted destination.
func readUOTRequest(r io.Reader) (isConnect bool, destination uotAddress, err error) {
	var mode [1]byte
	if _, err = io.ReadFull(r, mode[:]); err != nil {
		return false, uotAddress{}, err
	}
	if mode[0] > 1 {
		return false, uotAddress{}, errUOTMalformed
	}
	destination, err = readSOCKSAddress(r)
	return mode[0] == 1, destination, err
}

// readUOTFrame reads one datagram. In connect mode the destination is fixed by
// the request header; otherwise each frame carries its own sing/common/uot addr.
func readUOTFrame(r io.Reader, isConnect bool, fixed uotAddress, maxPayload int) (uotAddress, []byte, error) {
	destination := fixed
	if !isConnect {
		var err error
		destination, err = readPacketAddress(r)
		if err != nil {
			return uotAddress{}, nil, err
		}
	}
	var size [2]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return uotAddress{}, nil, err
	}
	n := int(binary.BigEndian.Uint16(size[:]))
	if n == 0 || n > maxPayload {
		return uotAddress{}, nil, fmt.Errorf("%w: payload length %d outside limit", errUOTMalformed, n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return uotAddress{}, nil, err
	}
	return destination, payload, nil
}

func writeUOTFrame(w io.Writer, isConnect bool, destination uotAddress, payload []byte, maxPayload int) error {
	if len(payload) == 0 || len(payload) > maxPayload || len(payload) > 65535 {
		return fmt.Errorf("%w: payload length %d outside limit", errUOTMalformed, len(payload))
	}
	if !isConnect {
		if err := writePacketAddress(w, destination); err != nil {
			return err
		}
	}
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(payload)))
	if err := writeFull(w, size[:]); err != nil {
		return err
	}
	return writeFull(w, payload)
}
