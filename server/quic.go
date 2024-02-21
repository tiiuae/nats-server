package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	"github.com/quic-go/quic-go"
)

type quicConnStream struct {
	quic.Connection
	quic.Stream
}

func (c *quicConnStream) Close() error {
	return errors.Join(
		c.Stream.Close(),
		c.Connection.CloseWithError(0, "connection closed"),
	)
}

type quicListener struct {
	*quic.Listener
}

func (l *quicListener) Addr() net.Addr {
	a := l.Listener.Addr().(*net.UDPAddr)
	return &net.TCPAddr{
		IP:   a.IP,
		Port: a.Port,
		Zone: a.Zone,
	}
}

func (l *quicListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept(context.Background())
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		_ = conn.CloseWithError(0, "failed to accept stream")
		return nil, fmt.Errorf("conn.OpenStreamSync: %w", err)
	}
	return &quicConnStream{
		Connection: conn,
		Stream:     stream,
	}, nil
}

func quicListen(address string, tlsConfig *tls.Config, quicConfig *quic.Config) (net.Listener, error) {
	l, err := quic.ListenAddr(address, tlsConfig, quicConfig)
	if err != nil {
		return nil, fmt.Errorf("quic.ListenAddr: %w", err)
	}
	return &quicListener{Listener: l}, nil
}
