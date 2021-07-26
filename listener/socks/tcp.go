package socks

import (
	"io"
	"io/ioutil"
	"net"

	"github.com/Dreamacro/clash/adapter/inbound"
	N "github.com/Dreamacro/clash/common/net"
	C "github.com/Dreamacro/clash/constant"
	authStore "github.com/Dreamacro/clash/listener/auth"
	"github.com/Dreamacro/clash/transport/socks4"
	"github.com/Dreamacro/clash/transport/socks5"
)

type Listener struct {
	listener net.Listener
	address  string
	closed   bool
}

func New(addr string, in chan<- C.ConnContext) (*Listener, error) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	sl := &Listener{l, addr, false}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				if sl.closed {
					break
				}
				continue
			}
			go handleSocks(c, in)
		}
	}()

	return sl, nil
}

func (l *Listener) Close() {
	l.closed = true
	l.listener.Close()
}

func (l *Listener) Address() string {
	return l.address
}

func handleSocks(conn net.Conn, in chan<- C.ConnContext) {
	bufConn := N.NewBufferedConn(conn)
	head, err := bufConn.Peek(1)
	if err != nil {
		conn.Close()
		return
	}

	switch head[0] {
	case socks4.Version:
		HandleSocks4(bufConn, in)
	case socks5.Version:
		HandleSocks5(bufConn, in)
	default:
		conn.Close()
	}
}

func HandleSocks4(conn net.Conn, in chan<- C.ConnContext) {
	addr, _, err := socks4.ServerHandshake(conn, authStore.Authenticator())
	if err != nil {
		conn.Close()
		return
	}
	if c, ok := conn.(*net.TCPConn); ok {
		c.SetKeepAlive(true)
	}
	in <- inbound.NewSocket(socks5.ParseAddr(addr), conn, C.SOCKS)
}

func HandleSocks5(conn net.Conn, in chan<- C.ConnContext) {
	target, command, err := socks5.ServerHandshake(conn, authStore.Authenticator())
	if err != nil {
		conn.Close()
		return
	}
	if c, ok := conn.(*net.TCPConn); ok {
		c.SetKeepAlive(true)
	}
	if command == socks5.CmdUDPAssociate {
		defer conn.Close()
		io.Copy(ioutil.Discard, conn)
		return
	}
	in <- inbound.NewSocket(target, conn, C.SOCKS)
}
