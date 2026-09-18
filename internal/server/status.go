package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/quangdz/ssh-relay/internal/policy"
)

// bindingDoc is one entry of the status document's bindings array.
type bindingDoc struct {
	Alias              string `json:"alias"`
	ListenAddress      string `json:"listen_address"`
	CreatedAt          string `json:"created_at"`
	SSHCommand         string `json:"ssh_command"`
	CustomUserTemplate string `json:"custom_user_template"`
	BridgesUsed        int32  `json:"bridges_used"`
	BridgesMax         int    `json:"bridges_max"`
}

type sessionsDoc struct {
	Used    int `json:"used"`
	Allowed int `json:"allowed"`
}

type statusDoc struct {
	IP           string       `json:"ip"`
	RelayVersion string       `json:"relay_version"`
	Sessions     sessionsDoc  `json:"sessions"`
	Bindings     []bindingDoc `json:"bindings"`
}

// buildStatusDoc renders the machine-readable document shared by the `json`
// status endpoint and the `ssh+json` control shell (ARCHITECTURE §4.4).
// excludeSelf drops the querying connection's own slot from sessions.used.
func (s *Server) buildStatusDoc(ip string, excludeSelf bool, eff policy.Effective) ([]byte, error) {
	used := s.deps.IPLimit.Used(ip)
	if excludeSelf && used > 0 {
		used--
	}
	doc := statusDoc{
		IP:           ip,
		RelayVersion: s.deps.Version,
		Sessions:     sessionsDoc{Used: used, Allowed: eff.MaxSessionsPerIP},
		Bindings:     []bindingDoc{},
	}
	bs := s.deps.Registry.ByOwnerIP(ip)
	sort.Slice(bs, func(i, j int) bool { return bs[i].Created().Before(bs[j].Created()) })
	for _, b := range bs {
		doc.Bindings = append(doc.Bindings, bindingDoc{
			Alias:              b.Alias,
			ListenAddress:      listenAddressLabel(b.ListenAddr),
			CreatedAt:          b.Created().UTC().Format(time.RFC3339),
			SSHCommand:         s.sshCommand(b.Alias),
			CustomUserTemplate: s.sshUserCommand(b.Alias),
			BridgesUsed:        b.Bridges(),
			BridgesMax:         b.MaxBridges,
		})
	}
	return marshalStatusDoc(doc)
}

// marshalStatusDoc encodes the document without HTML escaping (Go's default
// json.Marshal would turn `<user>` into `\u003cuser\u003e`) and without the
// encoder's trailing newline (call sites add their own line ending).
func marshalStatusDoc(doc statusDoc) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'}), nil
}

func listenAddressLabel(addr string) string {
	if addr == "" {
		return "(auto)"
	}
	return addr
}

// handleStatus serves the pure status endpoint: one JSON document, then the
// connection closes. No forwarding is honored here (ARCHITECTURE §4.4).
func (s *Server) handleStatus(ctx context.Context, sc *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request, state *st) {
	defer sc.Close()

	go s.handleStatusRequests(reqs)

	for nch := range chans {
		if nch.ChannelType() != "session" {
			nch.Reject(ssh.UnknownChannelType, "status connections support one session only")
			continue
		}
		ch, chReqs, err := nch.Accept()
		if err != nil {
			continue
		}
		// Answer session setup inline; write the document once the client
		// asks for its shell/exec so the reply precedes the output. With a
		// PTY the document is CRLF-terminated for terminal display; piped
		// clients get plain LF (jq-safe).
		pty := false
		for req := range chReqs {
			switch req.Type {
			case "pty-req":
				pty = true
				req.Reply(true, nil)
			case "shell", "exec":
				req.Reply(true, nil)
				doc, derr := s.buildStatusDoc(state.ip, true, state.eff)
				if derr != nil {
					fmt.Fprintf(ch, "error building status document: %v\r\n", derr)
				} else {
					ch.Write(toTerminal(append(doc, '\n'), pty))
				}
				ch.SendRequest("exit-status", false, ssh.Marshal(exitStatusMsg{Status: 0}))
				ch.Close()
				return
			case "env":
				req.Reply(true, nil)
			default:
				if req.WantReply {
					req.Reply(false, nil)
				}
			}
		}
	}
}

func (s *Server) handleStatusRequests(reqs <-chan *ssh.Request) {
	for req := range reqs {
		switch req.Type {
		case "keepalive@openssh.com":
			req.Reply(true, nil)
		case "tcpip-forward", "cancel-tcpip-forward":
			// Status connections forward nothing.
			req.Reply(false, nil)
		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}
