package derphttp

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derpserver"
	"tailscale.com/net/netmon"
	"tailscale.com/tstest"
	"tailscale.com/types/key"
)

// TestClientSetAuthSnapshot checks the SetAuth/authSnapshot pair:
// a rotation is visible to the next snapshot, and rotating
// concurrently with snapshots must not race (run under -race).
func TestClientSetAuthSnapshot(t *testing.T) {
	c, err := NewClient(key.NewNode(), "http://127.0.0.1:1", t.Logf, netmon.NewStatic())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	c.SetAuth("alice", "t1")
	if u, tok := c.authSnapshot(); u != "alice" || tok != "t1" {
		t.Errorf("authSnapshot after SetAuth = %q, %q; want alice, t1", u, tok)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := range 1000 {
			c.SetAuth("alice", "t"+string(rune('0'+i%10)))
		}
	}()
	go func() {
		defer wg.Done()
		for range 1000 {
			c.authSnapshot()
		}
	}()
	wg.Wait()
}

// TestClientSetAuthCarriesToReconnect verifies that credentials
// rotated via SetAuth are sent on the client's next connection:
// after the connection breaks (as when a derper restarts and the
// client reconnects), the reconnection must present the rotated
// token, not the one current when the client was created. Before
// SetAuth existed, the reconnection kept re-sending the stale
// token forever.
func TestClientSetAuthCarriesToReconnect(t *testing.T) {
	tstest.Replace(t, RetryInterval, 50*time.Millisecond)

	// A fake admission controller recording the credentials of
	// every check and admitting everyone, so the test observes
	// which token each connection presented.
	var mu sync.Mutex
	var got []string
	admit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username string
			AuthHash string
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		mu.Lock()
		got = append(got, req.AuthHash)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"Allow":true}`))
	}))
	defer admit.Close()

	serverPrivateKey := key.NewNode()
	s := derpserver.New(serverPrivateKey, t.Logf)
	defer s.Close()
	s.SetVerifyClientURL(admit.URL)
	httpsrv := &http.Server{Handler: derpserver.Handler(s)}
	defer httpsrv.Close()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go httpsrv.Serve(ln)

	netMon := netmon.NewStatic()
	client, err := NewClient(key.NewNode(), "http://"+ln.Addr().String(), t.Logf, netMon)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	client.SetAuth("alice", "token1")
	if err := client.Connect(context.Background()); err != nil {
		t.Fatalf("Connect with token1: %v", err)
	}
	// Wait for the handshake to complete: Recv until the
	// ServerInfoMessage ends it.
	for {
		m, err := client.Recv()
		if err != nil {
			t.Fatalf("client first Recv: %v", err)
		}
		if _, ok := m.(derp.ServerInfoMessage); ok {
			break
		}
	}

	// A Recv loop drives reconnection after the connection breaks.
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			_, err := client.Recv()
			if err != nil {
				select {
				case <-done:
					return
				default:
				}
			}
		}
	}()

	waitForToken := func(tok string) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			mu.Lock()
			n := len(got)
			last := ""
			if n > 0 {
				last = got[n-1]
			}
			mu.Unlock()
			if last == tok {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("admission controller never saw token %q; got %q", tok, got)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	waitForToken("token1")

	// Rotate the token, then break the connection as a derper
	// restart would. The reconnection must present token2.
	client.SetAuth("alice", "token2")
	client.BreakConnection(client)
	waitForToken("token2")

	mu.Lock()
	defer mu.Unlock()
	if len(got) == 0 || got[0] != "token1" {
		t.Errorf("first admission check = %q; want token1 (all: %q)", got[0], got)
	}
	for _, tok := range got[1:] {
		if tok != "token2" {
			t.Errorf("post-rotation admission check = %q; want only token2 (all: %q)", tok, got)
		}
	}
}
