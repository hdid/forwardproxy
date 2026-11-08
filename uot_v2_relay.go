package forwardproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const (
	uotMaxDatagram = 4096
	uotMaxSessions = 512
)

var uotActiveSessions atomic.Int32

// serveUOT handles one UoT v2 HTTP/2 CONNECT stream. It intentionally uses a
// dedicated SOCKS5 UDP ASSOCIATE control connection and relay socket per stream.
func (h *Handler) serveUOT(w http.ResponseWriter, r *http.Request) error {
	if r.ProtoMajor != 2 {
		return caddyhttp.Error(http.StatusBadRequest, errors.New("UoT requires HTTP/2 CONNECT"))
	}
	if h.upstream == nil || (h.upstream.Scheme != "socks5" && h.upstream.Scheme != "socks5h") {
		return caddyhttp.Error(http.StatusBadGateway, errors.New("UoT requires a SOCKS5 upstream"))
	}
	if uotActiveSessions.Add(1) > uotMaxSessions {
		uotActiveSessions.Add(-1)
		return caddyhttp.Error(http.StatusServiceUnavailable, errors.New("UDP session limit reached"))
	}
	defer uotActiveSessions.Add(-1)

	// The HTTP/2 stream is already authenticated by ServeHTTP's existing
	// credentials check. No second authentication layer is introduced.
	w.WriteHeader(http.StatusOK)
	if err := http.NewResponseController(w).Flush(); err != nil {
		return err
	}
	defer r.Body.Close()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	isConnect, fixed, err := readUOTRequest(r.Body)
	if err != nil {
		return fmt.Errorf("invalid UoT request: %w", err)
	}
	if isConnect {
		if err := h.authorizeUDP(fixed); err != nil {
			return err
		}
	}

	control, relay, err := h.openSOCKS5UDP(ctx)
	if err != nil {
		return fmt.Errorf("SOCKS5 UDP ASSOCIATE failed: %w", err)
	}
	defer control.Close()
	defer relay.Close()

	var writeMu sync.Mutex
	writeFrame := func(dst uotAddress, payload []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		if err := writeUOTFrame(w, isConnect, dst, payload, uotMaxDatagram); err != nil {
			return err
		}
		return http.NewResponseController(w).Flush()
	}

	// Client -> upstream. The request body is the sole reader for this stream.
	go func() {
		defer cancel()
		for {
			dst, payload, readErr := readUOTFrame(r.Body, isConnect, fixed, uotMaxDatagram)
			if readErr != nil {
				return
			}
			if !isConnect {
				if authErr := h.authorizeUDP(dst); authErr != nil {
					// A denied datagram is dropped; the association remains alive.
					continue
				}
			}
			packet, encErr := encodeSOCKS5Datagram(dst, payload)
			if encErr != nil {
				return
			}
			if _, writeErr := relay.Write(packet); writeErr != nil {
				return
			}
		}
	}()

	// Upstream -> client. One UDP socket and one HTTP/2 stream are isolated.
	buf := make([]byte, 65535)
	for {
		_ = relay.SetReadDeadline(time.Now().Add(120 * time.Second))
		n, _, readErr := relay.ReadFromUDP(buf)
		if readErr != nil {
			if ne, ok := readErr.(net.Error); ok && ne.Timeout() {
				return nil
			}
			if ctx.Err() != nil {
				return nil
			}
			return readErr
		}
		dst, payload, parseErr := decodeSOCKS5Datagram(buf[:n])
		if parseErr != nil {
			continue
		}
		if isConnect {
			dst = fixed
		} else if err := h.authorizeUDP(dst); err != nil {
			continue
		}
		if len(payload) > uotMaxDatagram {
			continue
		}
		if err := writeFrame(dst, payload); err != nil {
			return err
		}
	}
}

func (h *Handler) authorizeUDP(dst uotAddress) error {
	if dst.Port == 0 || !h.portIsAllowed(strconv.Itoa(int(dst.Port))) {
		return errors.New("UDP destination port is not allowed")
	}
	if ip := net.ParseIP(dst.Host); ip != nil {
		for _, rule := range h.aclRules {
			switch rule.tryMatch(ip, "") {
			case aclDecisionDeny:
				return errors.New("UDP destination IP is not allowed")
			case aclDecisionAllow:
				return nil
			}
		}
		return errors.New("UDP destination IP is not allowed")
	}
	host := strings.TrimSuffix(strings.ToLower(dst.Host), ".")
	if host == "" || strings.ContainsAny(host, " /\\\x00") {
		return errors.New("invalid UDP destination host")
	}
	for _, rule := range h.aclRules {
		if _, ok := rule.(*aclDomainRule); !ok {
			continue
		}
		switch rule.tryMatch(nil, host) {
		case aclDecisionDeny:
			return errors.New("UDP destination domain is not allowed")
		case aclDecisionAllow:
			return nil
		}
	}
	// Domain destinations are intentionally not resolved locally. The Xray
	// SOCKS5 upstream must enforce post-resolution private-address policy.
	return nil
}

func (h *Handler) openSOCKS5UDP(ctx context.Context) (net.Conn, *net.UDPConn, error) {
	var d net.Dialer
	control, err := d.DialContext(ctx, "tcp", h.upstream.Host)
	if err != nil {
		return nil, nil, err
	}
	fail := func(err error) (net.Conn, *net.UDPConn, error) {
		_ = control.Close()
		return nil, nil, err
	}
	_ = control.SetDeadline(time.Now().Add(10 * time.Second))

	methods := []byte{0x00}
	if h.upstream.User != nil {
		methods = append(methods, 0x02)
	}
	hello := append([]byte{0x05, byte(len(methods))}, methods...)
	if err := writeFull(control, hello); err != nil {
		return fail(err)
	}
	var choice [2]byte
	if _, err := io.ReadFull(control, choice[:]); err != nil {
		return fail(err)
	}
	if choice[0] != 0x05 || choice[1] == 0xff {
		return fail(errors.New("SOCKS5 upstream rejected authentication methods"))
	}
	if choice[1] == 0x02 {
		user := h.upstream.User.Username()
		pass, _ := h.upstream.User.Password()
		if len(user) > 255 || len(pass) > 255 {
			return fail(errors.New("SOCKS5 credentials are too long"))
		}
		auth := []byte{0x01, byte(len(user))}
		auth = append(auth, user...)
		auth = append(auth, byte(len(pass)))
		auth = append(auth, pass...)
		if err := writeFull(control, auth); err != nil {
			return fail(err)
		}
		var authReply [2]byte
		if _, err := io.ReadFull(control, authReply[:]); err != nil {
			return fail(err)
		}
		if authReply[1] != 0x00 {
			return fail(errors.New("SOCKS5 upstream authentication failed"))
		}
	} else if choice[1] != 0x00 {
		return fail(errors.New("SOCKS5 upstream selected an unsupported method"))
	}
	if err := writeFull(control, []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return fail(err)
	}
	bound, err := readSOCKS5Reply(control)
	if err != nil {
		return fail(err)
	}
	host := bound.Host
	if ip := net.ParseIP(host); ip == nil || ip.IsUnspecified() {
		host = h.upstream.Hostname()
	}
	port := bound.Port
	if port == 0 {
		return fail(errors.New("SOCKS5 upstream returned an empty UDP relay port"))
	}
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		return fail(err)
	}
	relay, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return fail(err)
	}
	_ = control.SetDeadline(time.Time{})
	return control, relay, nil
}

func readSOCKS5Reply(r io.Reader) (uotAddress, error) {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return uotAddress{}, err
	}
	if head[0] != 0x05 || head[1] != 0x00 || head[2] != 0x00 {
		return uotAddress{}, errors.New("SOCKS5 UDP ASSOCIATE rejected")
	}
	var a uotAddress
	switch head[3] {
	case 0x01:
		var b [6]byte
		if _, err := io.ReadFull(r, b[:]); err != nil { return a, err }
		a.Host, a.Port = net.IP(b[:4]).String(), binary.BigEndian.Uint16(b[4:])
	case 0x04:
		var b [18]byte
		if _, err := io.ReadFull(r, b[:]); err != nil { return a, err }
		a.Host, a.Port = net.IP(b[:16]).String(), binary.BigEndian.Uint16(b[16:])
	case 0x03:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil { return a, err }
		b := make([]byte, int(n[0])+2)
		if _, err := io.ReadFull(r, b); err != nil { return a, err }
		a.Host, a.Port = string(b[:len(b)-2]), binary.BigEndian.Uint16(b[len(b)-2:])
	default:
		return a, errors.New("SOCKS5 upstream returned an invalid address type")
	}
	return a, nil
}

func encodeSOCKS5Datagram(dst uotAddress, payload []byte) ([]byte, error) {
	var b strings.Builder
	if err := writeSOCKSAddress(&b, dst); err != nil { return nil, err }
	addr := []byte(b.String())
	packet := make([]byte, 3+len(addr)+len(payload))
	copy(packet[3:], addr)
	copy(packet[3+len(addr):], payload)
	return packet, nil
}

func decodeSOCKS5Datagram(packet []byte) (uotAddress, []byte, error) {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return uotAddress{}, nil, errors.New("invalid SOCKS5 UDP packet")
	}
	reader := strings.NewReader(string(packet[3:]))
	dst, err := readSOCKSAddress(reader)
	if err != nil { return uotAddress{}, nil, err }
	offset := len(packet) - reader.Len()
	if offset >= len(packet) { return uotAddress{}, nil, errors.New("empty SOCKS5 UDP payload") }
	return dst, packet[3+offset:], nil
}

var _ = url.URL{}
