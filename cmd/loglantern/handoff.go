package main

import (
	"net"
	"sync"
)

// handoff keeps one listening socket across config reloads: each app generation gets its own
// listener view; connections that arrive during a reload wait for the next generation.
type handoff struct {
	ln    net.Listener
	conns chan net.Conn
	back  chan net.Conn // taken by a generation that was closing
	done  chan struct{}
}

func newHandoff(ln net.Listener) *handoff {
	h := &handoff{ln: ln, conns: make(chan net.Conn), back: make(chan net.Conn, 64), done: make(chan struct{})}
	go func() {
		defer close(h.done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			h.conns <- c
		}
	}()
	return h
}

// Close stops accepting for good.
func (h *handoff) Close() error { return h.ln.Close() }

func (h *handoff) generation() net.Listener { return &genListener{h: h, closed: make(chan struct{})} }

type genListener struct {
	h      *handoff
	closed chan struct{}
	once   sync.Once
}

func (g *genListener) Accept() (net.Conn, error) {
	var c net.Conn
	select {
	case <-g.closed:
		return nil, net.ErrClosed
	case c = <-g.h.back:
	default:
		select {
		case <-g.closed:
			return nil, net.ErrClosed
		case <-g.h.done:
			return nil, net.ErrClosed
		case c = <-g.h.back:
		case c = <-g.h.conns:
		}
	}
	select {
	case <-g.closed: // closed meanwhile: hand the connection to the next generation
		select {
		case g.h.back <- c:
		default:
			c.Close()
		}
		return nil, net.ErrClosed
	default:
		return c, nil
	}
}

func (g *genListener) Close() error {
	g.once.Do(func() { close(g.closed) })
	return nil
}

func (g *genListener) Addr() net.Addr { return g.h.ln.Addr() }
