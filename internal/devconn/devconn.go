// Package devconn bridges SSH channels to net.Conn and dials the device's
// sshd through the reverse tunnel (Phase 2 of the two-phase SSH design).
package devconn

import (
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// forwardedTCPPayload mirrors RFC 4254 §7.2 "forwarded-tcpip" open data.
type forwardedTCPPayload struct {
	ConnectedAddr  string
	ConnectedPort  uint32
	OriginatorAddr string
	OriginatorPort uint32
}

// DialThrough opens a forwarded-tcpip channel on the device's control
// connection. The device's ssh client accepts it (it registered the remote
// forward) and dials its local target. The channel is wrapped as a net.Conn
// so the relay can run its Phase-2 SSH client handshake straight through it.
//
// listenAddr/virtualPort must match exactly what the device registered in its
// tcpip-forward request and what the relay replied — OpenSSH matches incoming
// forwarded-tcpip opens against its own forward table.
func DialThrough(conn *ssh.ServerConn, listenAddr string, virtualPort uint32, originIP string) (net.Conn, error) {
	payload := forwardedTCPPayload{
		ConnectedAddr:  listenAddr,
		ConnectedPort:  virtualPort,
		OriginatorAddr: originIP,
		OriginatorPort: 0,
	}
	ch, _, err := conn.OpenChannel("forwarded-tcpip", ssh.Marshal(payload))
	if err != nil {
		return nil, fmt.Errorf("open forwarded-tcpip through tunnel: %w", err)
	}
	return Wrap(ch, "relay", "device/"+listenAddr), nil
}

// channelConn adapts an ssh.Channel to net.Conn. Deadlines are unsupported by
// the SSH channel abstraction and are accepted as no-ops; lifecycle is managed
// by Close and the pumps' contexts.
type channelConn struct {
	ssh.Channel
	local  net.Addr
	remote net.Addr
}

// Wrap adapts ch into a net.Conn with descriptive addresses.
func Wrap(ch ssh.Channel, localName, remoteName string) net.Conn {
	return &channelConn{Channel: ch, local: Addr{network: "ssh", s: localName}, remote: Addr{network: "ssh", s: remoteName}}
}

func (c *channelConn) LocalAddr() net.Addr                { return c.local }
func (c *channelConn) RemoteAddr() net.Addr               { return c.remote }
func (c *channelConn) SetDeadline(t time.Time) error      { return nil }
func (c *channelConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *channelConn) SetWriteDeadline(t time.Time) error { return nil }

// Addr is a trivial net.Addr implementation ("ssh" network).
type Addr struct {
	network string
	s       string
}

func (a Addr) Network() string { return a.network }
func (a Addr) String() string  { return a.s }
