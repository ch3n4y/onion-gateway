package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// TorClient is a minimal Tor control-port client: just enough of the protocol to
// authenticate with the cookie, then ADD_ONION / DEL_ONION ephemeral v3 services.
//
// Keys are never handed to Tor's config file: ADD_ONION returns the private key
// blob the first time, we store it, and on restart we replay it to get the exact
// same .onion address back.
type TorClient struct {
	addr       string
	cookiePath string
}

func NewTorClient(addr, cookiePath string) *TorClient {
	return &TorClient{addr: addr, cookiePath: cookiePath}
}

type torConn struct {
	nc   net.Conn
	r    *bufio.Reader
	data []string
}

func dialTorControl(ctx context.Context, addr string) (*torConn, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tc := &torConn{nc: nc, r: bufio.NewReader(nc)}
	// Tor 0.4.9 does not send the PROTOCOLINFO greeting unsolicited (observed on
	// Alpine's build), so the client has to ask first and would otherwise block
	// until the read deadline.
	if _, err := tc.cmd("PROTOCOLINFO 1"); err != nil {
		nc.Close()
		return nil, fmt.Errorf("tor protocolinfo: %w", err)
	}
	return tc, nil
}

func (tc *torConn) Close() error { return tc.nc.Close() }

func (tc *torConn) readReply() (map[string]string, error) {
	out := map[string]string{}
	tc.data = nil
	if err := tc.nc.SetReadDeadline(time.Now().Add(20 * time.Second)); err != nil {
		return out, err
	}
	for {
		line, err := tc.r.ReadString('\n')
		if err != nil {
			return out, err
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) < 3 {
			continue
		}
		code := line[:3]
		sep := byte(' ')
		rest := ""
		if len(line) > 3 {
			sep = line[3]
			if len(line) > 4 {
				rest = line[4:]
			}
		}
		switch sep {
		case '-':
			if k, v, ok := strings.Cut(rest, "="); ok {
				out[k] = v
			}
		case '+':
			// Multi-line data block, terminated by a lone ".". Keep the payload:
			// GETINFO answers only arrive this way.
			for {
				dl, err := tc.r.ReadString('\n')
				if err != nil {
					return out, err
				}
				dl = strings.TrimRight(dl, "\r\n")
				if dl == "." {
					break
				}
				tc.data = append(tc.data, dl)
			}
		default:
			if code[0] == '2' {
				return out, nil
			}
			return out, fmt.Errorf("tor control error: %s %s", code, rest)
		}
	}
}

func (tc *torConn) cmd(command string) (map[string]string, error) {
	if err := tc.nc.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return nil, err
	}
	if _, err := tc.nc.Write([]byte(command + "\r\n")); err != nil {
		return nil, err
	}
	return tc.readReply()
}

func (t *TorClient) withConn(ctx context.Context, fn func(*torConn) error) error {
	tc, err := dialTorControl(ctx, t.addr)
	if err != nil {
		return err
	}
	defer tc.Close()

	raw, err := os.ReadFile(t.cookiePath)
	if err != nil {
		return fmt.Errorf("read tor control cookie %s: %w", t.cookiePath, err)
	}
	if len(raw) == 0 {
		return errors.New("tor control cookie is empty")
	}
	if _, err := tc.cmd("AUTHENTICATE " + hex.EncodeToString(raw)); err != nil {
		return fmt.Errorf("tor authenticate: %w", err)
	}
	return fn(tc)
}

// AddOnion publishes an onion service. With an empty key a new address is
// generated and its private key returned; with an existing key blob the same
// address is restored.
func (t *TorClient) AddOnion(ctx context.Context, key, virtualPort, target string) (onionID, privKey string, err error) {
	var reply map[string]string
	err = t.withConn(ctx, func(tc *torConn) error {
		cmd := "ADD_ONION NEW:ED25519-V3"
		if key != "" {
			cmd = "ADD_ONION " + key
		}
		// Detach: keep the service alive after this control connection closes. We
		// open a connection per operation, and without Detach tor would destroy the
		// onion service the moment we disconnect.
		cmd += fmt.Sprintf(" Port=%s,%s Flags=Detach", virtualPort, target)
		var e error
		reply, e = tc.cmd(cmd)
		return e
	})
	if err != nil {
		return "", "", err
	}
	onionID = strings.TrimSuffix(reply["ServiceID"], ".onion")
	if onionID == "" {
		return "", "", errors.New("tor returned no ServiceID")
	}
	if p := reply["PrivateKey"]; p != "" {
		privKey = p
	} else {
		privKey = key
	}
	return onionID, privKey, nil
}

func (t *TorClient) DelOnion(ctx context.Context, onionID string) error {
	id := strings.TrimSuffix(onionID, ".onion")
	return t.withConn(ctx, func(tc *torConn) error {
		_, err := tc.cmd("DEL_ONION " + id)
		return err
	})
}

// TorStatus is what the panel needs to show a meaningful connection state.
type TorStatus struct {
	Version   string
	Bootstrap int    // 0-100, 100 = ready
	Phase     string // e.g. "conn", "loading_descriptors", "done"
}

var (
	reProgress = regexp.MustCompile(`PROGRESS=(\d+)`)
	rePhase    = regexp.MustCompile(`TAG=(\w+)`)
)

func (t *TorClient) Status(ctx context.Context) (TorStatus, error) {
	var st TorStatus
	err := t.withConn(ctx, func(tc *torConn) error {
		reply, err := tc.cmd("GETINFO version status/bootstrap-phase")
		if err != nil {
			return err
		}
		st.Version = reply["version"]
		phase := reply["status/bootstrap-phase"]
		if m := reProgress.FindStringSubmatch(phase); m != nil {
			st.Bootstrap, _ = strconv.Atoi(m[1])
		}
		if m := rePhase.FindStringSubmatch(phase); m != nil {
			st.Phase = m[1]
		}
		return nil
	})
	return st, err
}

// IsAlreadyInUse reports whether tor refused an ADD_ONION because the address is
// already published. With Detach enabled a re-add after a panel restart hits
// this, and it is the desired state, not an error. Tor words it differently
// across versions ("already in use", "Onion address collision"), so match both.
func IsAlreadyInUse(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "already in use") || strings.Contains(msg, "collision")
}

// IsUnknownService reports whether tor no longer knows the service id, i.e. it is
// already gone and DEL_ONION can be considered successful.
func IsUnknownService(err error) bool {
	return err != nil && strings.Contains(err.Error(), "Unknown Onion Service id")
}

// DetachedOnions lists the services tor is actually running. Detached services
// outlive the control connection that created them, which is exactly what the
// panel needs to verify its state against reality.
func (t *TorClient) DetachedOnions(ctx context.Context) ([]string, error) {
	var ids []string
	err := t.withConn(ctx, func(tc *torConn) error {
		reply, err := tc.cmd("GETINFO onions/detached")
		if err != nil {
			return err
		}
		// Tor uses two reply shapes for GETINFO: a single "250-key=value" line for
		// one value, and a "+"-style data block for several. Handle both, treating
		// whitespace and newlines alike as separators.
		raw := reply["onions/detached"]
		for _, line := range tc.data {
			raw += " " + line
		}
		for _, f := range strings.Fields(raw) {
			if f = strings.TrimSuffix(f, ".onion"); f != "" {
				ids = append(ids, f)
			}
		}
		return nil
	})
	return ids, err
}
