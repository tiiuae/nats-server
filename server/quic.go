package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	quicScheme     = "quic"
	quicLeafScheme = "quic-leaf"
)

var defaultQUICConfig = &quic.Config{
	KeepAlivePeriod: 10 * time.Second,
	EnableDatagrams: true,
}

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
	listener  *quic.Listener
	transport *quic.Transport
}

func (l *quicListener) Addr() net.Addr {
	a := l.listener.Addr().(*net.UDPAddr)
	return &net.TCPAddr{
		IP:   a.IP,
		Port: a.Port,
		Zone: a.Zone,
	}
}

func (l *quicListener) Accept() (net.Conn, error) {
	conn, err := l.listener.Accept(context.Background())
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

func (l *quicListener) Close() error {
	return l.listener.Close()
}

func (l *quicListener) CloseTransportAndConn() error {
	return errors.Join(l.transport.Close(), l.transport.Conn.Close())
}

type srvQUIC struct {
	listener       *quicListener
	listenerErr    error
	connectURLs    []string
	connectURLsMap refCountedUrlSet
	authOverride   bool // indicate if there is auth override in QUIC config
}

func (s *Server) startQUICServer() {
	if s.isShuttingDown() {
		return
	}

	sopts := s.getOpts()
	o := &sopts.QUIC

	port := o.Port
	if port == -1 {
		port = 0
	}
	hp := net.JoinHostPort(o.Host, strconv.Itoa(port))

	// We are enforcing (when validating the options) the use of TLS, but the
	// code was originally supporting both modes. The reason for TLS only is
	// that we expect users to send JWTs with bearer tokens and we want to
	// avoid the possibility of it being "intercepted".

	s.mu.Lock()
	ql, err := s.quicListen(hp, o.TLSConfig, o)
	s.quic.listenerErr = err
	if err != nil {
		s.mu.Unlock()
		s.Fatalf("Unable to listen for QUIC connections: %v", err)
		return
	}
	if port == 0 {
		o.Port = ql.Addr().(*net.TCPAddr).Port
	}
	s.Noticef("Listening for QUIC connections on quic://%s:%d", o.Host, o.Port)

	s.quic.connectURLs, err = s.getConnectURLs(o.Advertise, o.Host, o.Port)
	if err != nil {
		s.Fatalf("Unable to get QUIC connect URLs: %v", err)
		ql.Close()
		s.mu.Unlock()
		return
	}
	go s.acceptConnections(ql, "QUIC", func(conn net.Conn) {
		s.createQUICClient(conn)
	}, func(err error) bool {
		if s.isLameDuckMode() {
			// Signal that we are not accepting new clients
			s.ldmCh <- true
			// Now wait for the Shutdown...
			<-s.quitCh
			return true
		}
		return false
	})
	s.quic.listener = ql
	s.mu.Unlock()
}

func (s *Server) quicListen(hp string, tlsConfig *tls.Config, o *QUICOpts) (ql *quicListener, err error) {
	if tlsConfig == nil {
		return nil, errors.New("QUIC connections require TLS configuration")
	}
	tlsConfig = tlsConfig.Clone()
	tlsConfig.GetConfigForClient = s.quicGetTLSConfig

	addr, err := net.ResolveUDPAddr("udp", hp)
	if err != nil {
		return nil, fmt.Errorf("net.ResolveUDPAddr: %w", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("net.ListenUDP: %w", err)
	}
	ql = &quicListener{transport: &quic.Transport{Conn: conn}}
	if o.QUICConfig == nil {
		ql.listener, err = ql.transport.Listen(tlsConfig, &quic.Config{
			HandshakeIdleTimeout: o.HandshakeIdleTimeout,
		})
	} else {
		ql.listener, err = ql.transport.Listen(tlsConfig, o.QUICConfig.Clone())
	}
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return ql, nil
}

func (s *Server) quicGetTLSConfig(_ *tls.ClientHelloInfo) (*tls.Config, error) {
	return s.getOpts().QUIC.TLSConfig, nil
}

func (s *Server) createQUICClient(conn net.Conn) *client {
	// Snapshot server options.
	opts := s.getOpts()

	maxPay := int32(opts.MaxPayload)
	maxSubs := int32(opts.MaxSubs)
	// For system, maxSubs of 0 means unlimited, so re-adjust here.
	if maxSubs == 0 {
		maxSubs = -1
	}
	now := time.Now()

	c := &client{srv: s, nc: conn, opts: defaultOpts, mpay: maxPay, msubs: maxSubs, start: now, last: now}

	c.registerWithAccount(s.globalAccount())

	var info Info
	var authRequired bool

	s.mu.Lock()
	// Grab JSON info string
	info = s.copyInfo()
	if s.nonceRequired() {
		// Nonce handling
		var raw [nonceLen]byte
		nonce := raw[:]
		s.generateNonce(nonce)
		info.Nonce = string(nonce)
	}
	c.nonce = []byte(info.Nonce)
	authRequired = info.AuthRequired

	// Check to see if we have auth_required set but we also have a no_auth_user.
	// If so set back to false.
	if info.AuthRequired && opts.NoAuthUser != _EMPTY_ && opts.NoAuthUser != s.sysAccOnlyNoAuthUser {
		info.AuthRequired = false
	}

	s.totalClients++
	s.mu.Unlock()

	// Grab lock
	c.mu.Lock()
	if authRequired {
		c.flags.set(expectConnect)
	}

	// Initialize
	c.initClient()

	c.Debugf("Client connection created")

	// Send our information.
	c.sendProtoNow(c.generateClientInfoJSON(info))

	// Unlock to register
	c.mu.Unlock()

	// Register with the server.
	s.mu.Lock()
	// If server is not running, Shutdown() may have already gathered the
	// list of connections to close. It won't contain this one, so we need
	// to bail out now otherwise the readLoop started down there would not
	// be interrupted. Skip also if in lame duck mode.
	if !s.isRunning() || s.ldm {
		// There are some tests that create a server but don't start it,
		// and use "async" clients and perform the parsing manually. Such
		// clients would branch here (since server is not running). However,
		// when a server was really running and has been shutdown, we must
		// close this connection.
		if s.isShuttingDown() {
			conn.Close()
		}
		s.mu.Unlock()
		return c
	}

	// If there is a max connections specified, check that adding
	// this new client would not push us over the max
	if opts.MaxConn > 0 && len(s.clients) >= opts.MaxConn {
		s.mu.Unlock()
		c.maxConnExceeded()
		return nil
	}
	s.clients[c.cid] = c

	s.mu.Unlock()

	// Re-Grab lock
	c.mu.Lock()

	// Connection could have been closed while sending the INFO proto.
	if c.isClosed() {
		c.mu.Unlock()
		// We need to call closeConnection() to make sure that proper cleanup is done.
		c.closeConnection(WriteError)
		return nil
	}

	// Check for Auth. We schedule this timer after the TLS handshake to avoid
	// the race where the timer fires during the handshake and causes the
	// server to write bad data to the socket. See issue #432.
	if authRequired {
		c.setAuthTimer(secondsToDuration(opts.AuthTimeout))
	}

	// Do final client initialization

	// Set the Ping timer. Will be reset once connect was received.
	c.setPingTimer()

	// Spin up the read loop.
	s.startGoRoutine(func() { c.readLoop(nil) })

	s.startGoRoutine(func() { c.readDatagramLoop(nil) })

	// Spin up the write loop.
	s.startGoRoutine(func() { c.writeLoop() })

	c.Debugf("TLS handshake complete")
	cs := c.nc.(*quicConnStream).ConnectionState().TLS
	c.Debugf("TLS version %s, cipher suite %s", tlsVersion(cs.Version), tlsCipher(cs.CipherSuite))

	c.mu.Unlock()

	return c
}

type quicDialer struct {
	tlsConfig  *tls.Config
	quicConfig *quic.Config
}

func makeLeafQUICConfig(opts *QUICOpts, timeout time.Duration) (c *quic.Config) {
	if opts.QUICConfig == nil {
		c = defaultQUICConfig.Clone()
	} else {
		c = opts.QUICConfig.Clone()
	}
	if c.HandshakeIdleTimeout == 0 {
		c.HandshakeIdleTimeout = timeout
	}
	return c
}

func makeLeafQUICTLSConfig(remote *leafNodeCfg) *tls.Config {
	_, tlsConfig, tlsName, _ := leafNodeGetTLSConfigForSolicit(remote)
	if tlsConfig.ServerName == _EMPTY_ {
		// If the given url is a hostname, use this hostname for the
		// ServerName. If it is an IP, use the cfg's tlsName. If none
		// is available, resort to current IP.
		host := remote.getCurrentURL().Hostname()
		if tlsName != _EMPTY_ && net.ParseIP(host) != nil {
			host = tlsName
		}
		tlsConfig.ServerName = host
	}
	return tlsConfig
}

func (d *quicDialer) Dial(network, addr string) (net.Conn, error) {
	conn, err := quic.DialAddr(context.Background(), addr, d.tlsConfig, d.quicConfig)
	if err != nil {
		return nil, fmt.Errorf("quic.DialAddr: %w", err)
	}
	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		return nil, fmt.Errorf("conn.AcceptStream: %w", errors.Join(err, conn.CloseWithError(0, err.Error())))
	}
	return &quicConnStream{
		Connection: conn,
		Stream:     stream,
	}, nil
}

func isQUICURL(u *url.URL) bool {
	return u.Scheme == quicScheme || u.Scheme == quicLeafScheme
}
