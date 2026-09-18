package server

// In-process end-to-end tests: a fake device sshd (x/crypto/ssh server)
// registers into a live relay exactly like `ssh -R ...` does, then real flows
// run through the relay: registration, password pass-through bridges,
// direct-tcpip (allowed + gated), the exact TCP-forwarding warning, status
// JSON, per-IP limits and fail2ban.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/quangdz/ssh-relay/internal/devconn"
	"github.com/quangdz/ssh-relay/internal/guard"
	"github.com/quangdz/ssh-relay/internal/policy"
	"github.com/quangdz/ssh-relay/internal/registry"
)

// ---------- fake device sshd ----------

type fakeDevice struct {
	mu        sync.Mutex
	passwords []string
	sessions  []string
}

func (f *fakeDevice) serverConfig(t *testing.T) *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		// Only "devpass" authenticates; everything else is recorded and
		// refused so pass-through failures and fail2ban can be exercised.
		PasswordCallback: func(md ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			f.mu.Lock()
			f.passwords = append(f.passwords, string(password))
			f.mu.Unlock()
			if string(password) == "devpass" {
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("wrong password")
		},
	}
	cfg.AddHostKey(testHostKey(t))
	return cfg
}

// serveControl plays the device side of a `ssh -R` control connection:
// forwarded-tcpip opens are accepted and become fresh sshd sessions
// (Phase-2 handshakes land here), everything else mirrors an OpenSSH client.
func (f *fakeDevice) serveControl(t *testing.T, conn ssh.Conn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
	go func() {
		for req := range reqs {
			if req.Type == "keepalive@openssh.com" {
				req.Reply(true, nil)
				continue
			}
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}()
	for nch := range chans {
		switch nch.ChannelType() {
		case "forwarded-tcpip":
			ch, _, err := nch.Accept()
			if err != nil {
				continue
			}
			go func() {
				sc, chans2, reqs2, err := ssh.NewServerConn(devconn.Wrap(ch, "device", "relay"), f.serverConfig(t))
				if err != nil {
					ch.Close()
					return
				}
				go f.handle(sc, chans2, reqs2)
			}()
		default:
			nch.Reject(ssh.UnknownChannelType, "fake device: unsupported channel")
		}
	}
}

func (f *fakeDevice) handle(sc *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
	defer sc.Close()
	go func() {
		for req := range reqs {
			if req.Type == "keepalive@openssh.com" {
				req.Reply(true, nil)
				continue
			}
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}()
	for nch := range chans {
		switch nch.ChannelType() {
		case "session":
			ch, chReqs, err := nch.Accept()
			if err != nil {
				continue
			}
			go f.session(ch, chReqs)
		case "direct-tcpip":
			ch, _, err := nch.Accept()
			if err != nil {
				continue
			}
			go echoChannel(ch)
		default:
			nch.Reject(ssh.UnknownChannelType, "fake device: unsupported")
		}
	}
}

func (f *fakeDevice) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	for req := range reqs {
		switch req.Type {
		case "pty-req", "env", "shell", "exec", "subsystem":
			if req.Type == "exec" || req.Type == "subsystem" {
				f.mu.Lock()
				f.sessions = append(f.sessions, req.Type+":"+string(req.Payload))
				f.mu.Unlock()
			}
			req.Reply(true, nil)
			switch req.Type {
			case "shell", "exec":
				fmt.Fprint(ch, "welcome-device\r\n")
				ch.SendRequest("exit-status", false, ssh.Marshal(exitStatusMsg{Status: 0}))
				ch.Close()
				return
			case "subsystem":
				fmt.Fprint(ch, "sftp-ready\r\n")
				ch.SendRequest("exit-status", false, ssh.Marshal(exitStatusMsg{Status: 0}))
				ch.Close()
				return
			}
		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

func echoChannel(ch ssh.Channel) {
	defer ch.Close()
	io.Copy(ch, ch)
}

func testHostKey(t *testing.T) ssh.Signer {
	t.Helper()
	signer, err := LoadOrCreateHostKey(t.TempDir(), discardLogger())
	if err != nil {
		t.Fatalf("host key: %v", err)
	}
	return signer
}

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

// debugLogger writes relay-side logs to stderr for test debugging.
func debugLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// ---------- harness ----------

type stubPolicySource struct{ set *policy.PolicySet }

func (s *stubPolicySource) Current() *policy.PolicySet { return s.set }

type harness struct {
	t        *testing.T
	srv      *Server
	lis      net.Listener
	registry *registry.Registry
	ban      *guard.Fail2ban
	limiter  *guard.IPLimiter
	set      *policy.PolicySet
}

func newHarness(t *testing.T, mutate func(*policy.Effective)) *harness {
	t.Helper()
	base := policy.Effective{
		AllowTCPForwarding: true,
		AllowSFTP:          true,
		AllowSCP:           true,
		AllowX11Forwarding: false,
		BWLimitPerSec:      0,
		MaxSessionsPerIP:   3,
	}
	set := policy.EmptySet()
	if mutate != nil {
		mutate(&base)
	}
	h := &harness{
		t:        t,
		registry: registry.New(),
		ban:      guard.NewFail2ban(true),
		limiter:  guard.NewIPLimiter(),
		set:      set,
	}
	h.srv = New(Deps{
		BasePolicy:    base,
		Policy:        &stubPolicySource{set: set},
		Registry:      h.registry,
		IPLimit:       h.limiter,
		Ban:           h.ban,
		HostKey:       testHostKey(t),
		Log:           debugLogger(),
		Version:       "test",
		AdvertiseHost: "relay.test",
	})
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	h.lis = lis
	go h.srv.Serve(context.Background(), lis)
	t.Cleanup(func() { lis.Close() })
	return h
}

func (h *harness) addr() string { return h.lis.Addr().String() }

func (h *harness) clientDial(user, password string) (*ssh.Client, error) {
	return ssh.Dial("tcp", h.addr(), &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
}

type tcpipForwardClientMsg struct {
	Addr string
	Port uint32
}

type boundPortClientMsg struct {
	Port uint32
}

// registerDevice emulates `ssh -R <listenAddr>:0:127.0.0.1:22 ssh@relay`:
// the control connection stays open (holding the tunnel) and its device side
// serves Phase-2 sshd handshakes through forwarded-tcpip.
// deviceControlConn opens a `ssh@relay` control connection whose device side
// is served by dev. The raw ssh.Conn is returned (no NewClient wrapper: its
// channel handlers would race serveControl for forwarded-tcpip opens).
func (h *harness) deviceControlConn(t *testing.T, dev *fakeDevice, user string) ssh.Conn {
	t.Helper()
	conn, chans, reqs, err := ssh.NewClientConn(dialTCP(t, h.addr()), "", &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{}, // "none" — open device role
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("device conn (%s): %v", user, err)
	}
	t.Cleanup(func() { conn.Close() })
	go dev.serveControl(t, conn, chans, reqs)
	return conn
}

// controlShell opens the control session and returns its stdout reader after
// the shell request has been answered by the relay.
func controlShell(t *testing.T, conn ssh.Conn) io.Reader {
	t.Helper()
	ch, chReqs, err := conn.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("control session: %v", err)
	}
	go func() {
		for req := range chReqs {
			if req.WantReply {
				req.Reply(true, nil)
			}
		}
	}()
	if _, err := ch.SendRequest("shell", true, nil); err != nil {
		t.Fatalf("shell request: %v", err)
	}
	return ch
}

func (h *harness) registerDevice(t *testing.T, dev *fakeDevice, listenAddr string) string {
	t.Helper()
	conn := h.deviceControlConn(t, dev, "ssh")

	ok, payload, err := conn.SendRequest("tcpip-forward", true, ssh.Marshal(tcpipForwardClientMsg{Addr: listenAddr, Port: 0}))
	if err != nil || !ok {
		t.Fatalf("tcpip-forward: ok=%v err=%v", ok, err)
	}
	var bp boundPortClientMsg
	if err := ssh.Unmarshal(payload, &bp); err != nil || bp.Port == 0 {
		t.Fatalf("bound port reply: err=%v port=%d", err, bp.Port)
	}

	stdout := controlShell(t, conn)
	re := regexp.MustCompile(`Tunnel online: (\S+)`)
	buf := make([]byte, 4096)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatalf("never saw tunnel banner")
		}
		n, err := stdout.Read(buf)
		if n > 0 {
			if m := re.FindSubmatch(buf[:n]); m != nil {
				return string(m[1])
			}
		}
		if err != nil {
			t.Fatalf("banner read: %v", err)
		}
	}
}

func dialTCP(t *testing.T, addr string) net.Conn {
	t.Helper()
	nc, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	return nc
}

// ---------- tests ----------

func TestRegistrationAndBanner(t *testing.T) {
	h := newHarness(t, nil)
	dev := &fakeDevice{}

	alias := h.registerDevice(t, dev, "")
	if !strings.HasPrefix(alias, "d-") || len(alias) != 12 {
		t.Fatalf("alias = %q", alias)
	}
	if b, ok := h.registry.Lookup(alias); !ok || b.OwnerIP != "127.0.0.1" {
		t.Fatalf("binding not registered: %+v", b)
	}

	// Teardown frees the binding.
	// (control connections are closed by registerDevice's cleanup)
}

func TestCustomAliasAndRefusals(t *testing.T) {
	h := newHarness(t, nil)
	dev := &fakeDevice{}
	alias := h.registerDevice(t, dev, "myvps")
	if alias != "myvps" {
		t.Fatalf("custom alias not used: %q", alias)
	}
	if _, live := h.registry.Lookup("myvps"); !live {
		t.Fatalf("custom alias not registered")
	}

	control := h.deviceControlConn(t, dev, "ssh")

	// Duplicate alias refused.
	if ok, _, _ := control.SendRequest("tcpip-forward", true, ssh.Marshal(tcpipForwardClientMsg{Addr: "myvps", Port: 0})); ok {
		t.Fatalf("duplicate alias must be refused")
	}
	// Real-port forward toward the relay refused.
	if ok, _, _ := control.SendRequest("tcpip-forward", true, ssh.Marshal(tcpipForwardClientMsg{Addr: "", Port: 8080})); ok {
		t.Fatalf("real-port forward must be refused")
	}
	// Reserved alias refused.
	if ok, _, _ := control.SendRequest("tcpip-forward", true, ssh.Marshal(tcpipForwardClientMsg{Addr: "json", Port: 0})); ok {
		t.Fatalf("reserved alias must be refused")
	}

	// Bridge through the custom alias: same pass-through flow as generated
	// deviceIDs, proving the alias namespace is uniform end to end.
	client, err := h.clientDial("myvps", "devpass")
	if err != nil {
		t.Fatalf("custom alias client auth: %v", err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	out, err := sess.Output("probe")
	if err != nil {
		t.Fatalf("custom alias exec: %v", err)
	}
	if !strings.Contains(string(out), "welcome-device") {
		t.Fatalf("unexpected custom alias exec output %q", string(out))
	}

	// Teardown frees the binding: close the OWNING control connection.
	if b, ok := h.registry.Lookup("myvps"); ok {
		b.Owner.Close()
	}
	control.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, live := h.registry.Lookup("myvps"); !live {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("binding not released after disconnect")
}

func TestPasswordBridgeExec(t *testing.T) {
	h := newHarness(t, nil)
	dev := &fakeDevice{}
	alias := h.registerDevice(t, dev, "")

	client, err := h.clientDial("root+"+alias, "devpass")
	if err != nil {
		t.Fatalf("client auth: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	out, err := sess.Output("echo hi")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if !strings.Contains(string(out), "welcome-device") {
		t.Fatalf("unexpected exec output %q", string(out))
	}

	// Default user = root works without the user part.
	client2, err := h.clientDial(alias, "devpass")
	if err != nil {
		t.Fatalf("default-user auth: %v", err)
	}
	client2.Close()

	// Wrong password → auth failure; fail2ban window fills up but does not
	// ban a single miss.
	if _, err := h.clientDial("root+"+alias, "wrongpass"); err == nil {
		t.Fatalf("wrong password must fail")
	}
}

func TestDirectTCPIPAllowedAndGated(t *testing.T) {
	h := newHarness(t, nil)
	dev := &fakeDevice{}
	alias := h.registerDevice(t, dev, "")

	client, err := h.clientDial("root+"+alias, "devpass")
	if err != nil {
		t.Fatalf("client auth: %v", err)
	}
	defer client.Close()

	type dtcp struct {
		A string
		B uint32
		C string
		D uint32
	}
	ch, _, err := client.OpenChannel("direct-tcpip", ssh.Marshal(dtcp{"target.internal", 80, "10.0.0.1", 5555}))
	if err != nil {
		t.Fatalf("direct-tcpip open: %v", err)
	}
	ch.Write([]byte("ping"))
	buf := make([]byte, 4)
	readErr := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(ch, buf)
		readErr <- err
	}()
	select {
	case err := <-readErr:
		if err != nil || string(buf) != "ping" {
			t.Fatalf("echo mismatch: %q err=%v", buf, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("echo read timed out")
	}
	ch.Close()

	// Gate off (--allow-tcp-forwarding=false equivalent) and expect the
	// exact warning text.
	gated := newHarness(t, func(b *policy.Effective) { b.AllowTCPForwarding = false })
	alias2 := gated.registerDevice(t, &fakeDevice{}, "")
	client2, err := gated.clientDial("root+"+alias2, "devpass")
	if err != nil {
		t.Fatalf("gated client auth: %v", err)
	}
	defer client2.Close()
	_, _, err = client2.OpenChannel("direct-tcpip", ssh.Marshal(dtcp{"target.internal", 80, "10.0.0.1", 5555}))
	if err == nil {
		t.Fatalf("direct-tcpip must be refused when gated")
	}
	var openErr *ssh.OpenChannelError
	if !errorsAsOpenChannel(err, &openErr) || openErr.Message != TCPForwardWarning {
		t.Fatalf("wrong refusal: %v", err)
	}

	// Client-side -R (real port toward the relay) refused on gated conn too.
	if ok, _, _ := client2.SendRequest("tcpip-forward", true, ssh.Marshal(tcpipForwardClientMsg{Addr: "0.0.0.0", Port: 1234})); ok {
		t.Fatalf("client tcpip-forward must be refused")
	}
}

func errorsAsOpenChannel(err error, target **ssh.OpenChannelError) bool {
	oe, ok := err.(*ssh.OpenChannelError)
	if ok {
		*target = oe
	}
	return ok
}

func TestStatusEndpoint(t *testing.T) {
	h := newHarness(t, nil)
	alias := h.registerDevice(t, &fakeDevice{}, "")

	client, err := h.clientDial("json", "") // status role: password ignored
	if err != nil {
		t.Fatalf("status auth: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()
	out, err := sess.Output("")
	if err != nil {
		t.Fatalf("status output: %v", err)
	}
	var doc struct {
		IP           string `json:"ip"`
		RelayVersion string `json:"relay_version"`
		Sessions     struct {
			Used    int `json:"used"`
			Allowed int `json:"allowed"`
		} `json:"sessions"`
		Bindings []struct {
			Alias      string `json:"alias"`
			SSHCommand string `json:"ssh_command"`
		} `json:"bindings"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("bad json: %v\n%s", err, out)
	}
	if doc.IP != "127.0.0.1" || doc.RelayVersion != "test" || doc.Sessions.Allowed != 3 {
		t.Fatalf("doc fields wrong: %+v", doc)
	}
	if len(doc.Bindings) != 1 || doc.Bindings[0].Alias != alias {
		t.Fatalf("bindings wrong: %+v", doc.Bindings)
	}
	if doc.Bindings[0].SSHCommand != "ssh "+alias+"@relay.test" {
		t.Fatalf("ssh_command wrong: %q", doc.Bindings[0].SSHCommand)
	}
	if doc.Sessions.Used < 1 || doc.Sessions.Used > 2 {
		t.Fatalf("used quota off (device + status minus self): %d", doc.Sessions.Used)
	}
}

func TestDeviceJSONMode(t *testing.T) {
	h := newHarness(t, nil)
	dev := &fakeDevice{}
	_ = h.registerDevice(t, dev, "myvps")

	// A second ssh+json device connection that registers and reads JSON.
	conn := h.deviceControlConn(t, dev, "ssh+json")

	if ok, _, _ := conn.SendRequest("tcpip-forward", true, ssh.Marshal(tcpipForwardClientMsg{Addr: "", Port: 0})); !ok {
		t.Fatalf("ssh+json must support forwards")
	}
	stdout := controlShell(t, conn)
	jbuf := make([]byte, 8192)
	var out []byte
	jdeadline := time.Now().Add(5 * time.Second)
	for {
		if time.Now().After(jdeadline) {
			t.Fatalf("never saw json document")
		}
		n, rerr := stdout.Read(jbuf)
		if n > 0 {
			out = append(out, jbuf[:n]...)
			if bytesContains(out, `"ssh_command"`) {
				break
			}
		}
		if rerr != nil {
			t.Fatalf("json read: %v", rerr)
		}
	}
	if !bytesContains(out, `"alias": "myvps"`) {
		t.Fatalf("json doc missing first binding: %s", out)
	}
}

func bytesContains(b []byte, sub string) bool {
	return strings.Contains(string(b), sub)
}

func TestPerIPSessionLimit(t *testing.T) {
	// 3 = device conn + 2 client conns; the 4th client is refused.
	h := newHarness(t, func(b *policy.Effective) { b.MaxSessionsPerIP = 3 })
	dev := &fakeDevice{}
	alias := h.registerDevice(t, dev, "")

	var keep [2]*ssh.Client
	for i := range keep {
		c, err := h.clientDial("root+"+alias, "devpass")
		if err != nil {
			t.Fatalf("conn %d: %v", i, err)
		}
		keep[i] = c
		defer c.Close()
	}
	third, err := h.clientDial("root+"+alias, "devpass")
	if err != nil {
		t.Fatalf("third conn auth passes (limit enforced at channel open): %v", err)
	}
	defer third.Close()
	if _, _, err := third.OpenChannel("session", nil); err == nil {
		t.Fatalf("third session must be refused")
	}
}

func TestFail2banBansPasswordGuessers(t *testing.T) {
	h := newHarness(t, nil)
	dev := &fakeDevice{}
	alias := h.registerDevice(t, dev, "")

	for i := 0; i < guard.F2BThreshold; i++ {
		if _, err := h.clientDial("root+"+alias, fmt.Sprintf("guess-%d", i)); err == nil {
			t.Fatalf("guess %d must fail", i)
		}
	}
	// Banned pre-auth: even the correct password is now refused.
	if _, err := h.clientDial("root+"+alias, "devpass"); err == nil {
		t.Fatalf("banned IP must not authenticate")
	}
}
