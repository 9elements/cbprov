package qemu

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"
)

// qmp is a minimal synchronous QMP client.
type qmp struct {
	mu   sync.Mutex
	conn net.Conn
	r    *bufio.Reader
}

func dialQMP(ctx context.Context, path string) (*qmp, error) {
	var d net.Dialer
	for {
		c, err := d.DialContext(ctx, "unix", path)
		if err == nil {
			q := &qmp{conn: c, r: bufio.NewReader(c)}
			if _, err := q.r.ReadBytes('\n'); err != nil { // greeting
				c.Close()
				return nil, fmt.Errorf("qmp greeting: %w", err)
			}
			if _, err := q.run("qmp_capabilities", nil); err != nil {
				c.Close()
				return nil, err
			}
			return q, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("qmp connect %s: %w", path, err)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func (q *qmp) run(cmd string, args any) (json.RawMessage, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	req := map[string]any{"execute": cmd}
	if args != nil {
		req["arguments"] = args
	}
	b, _ := json.Marshal(req)
	q.conn.SetDeadline(time.Now().Add(60 * time.Second))
	defer q.conn.SetDeadline(time.Time{})
	if _, err := q.conn.Write(append(b, '\n')); err != nil {
		return nil, fmt.Errorf("qmp %s: %w", cmd, err)
	}
	for {
		line, err := q.r.ReadBytes('\n')
		if err != nil {
			return nil, fmt.Errorf("qmp %s: %w", cmd, err)
		}
		var resp struct {
			Return json.RawMessage `json:"return"`
			Error  *struct {
				Class string `json:"class"`
				Desc  string `json:"desc"`
			} `json:"error"`
			Event string `json:"event"`
		}
		if err := json.Unmarshal(line, &resp); err != nil {
			return nil, fmt.Errorf("qmp %s: bad response %q: %w", cmd, line, err)
		}
		switch {
		case resp.Event != "":
			continue
		case resp.Error != nil:
			return nil, fmt.Errorf("qmp %s: %s: %s", cmd, resp.Error.Class, resp.Error.Desc)
		default:
			return resp.Return, nil
		}
	}
}

func (q *qmp) close() error { return q.conn.Close() }
