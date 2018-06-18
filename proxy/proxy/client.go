// Copyright 2015 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/context"

	"github.com/GoogleCloudPlatform/cloudsql-proxy/internal/observability"
	"github.com/GoogleCloudPlatform/cloudsql-proxy/logging"

	"go.opencensus.io/stats"
	"go.opencensus.io/tag"
	"go.opencensus.io/trace"
)

const (
	DefaultRefreshCfgThrottle = time.Minute
	keepAlivePeriod           = time.Minute
)

// errNotCached is returned when the instance was not found in the Client's
// cache. It is an internal detail and is not actually ever returned to the
// user.
var errNotCached = errors.New("instance was not found in cache")

// Conn represents a connection from a client to a specific instance.
type Conn struct {
	Instance string
	Conn     net.Conn
}

// CertSource is how a Client obtains various certificates required for operation.
type CertSource interface {
	// Local returns a certificate that can be used to authenticate with the
	// provided instance.
	Local(instance string) (tls.Certificate, error)
	// Remote returns the instance's CA certificate, address, and name.
	Remote(instance string) (cert *x509.Certificate, addr, name string, err error)
}

// Client is a type to handle connecting to a Server. All fields are required
// unless otherwise specified.
type Client struct {
	// Port designates which remote port should be used when connecting to
	// instances. This value is defined by the server-side code, but for now it
	// should always be 3307.
	Port int
	// Required; specifies how certificates are obtained.
	Certs CertSource
	// Optionally tracks connections through this client. If nil, connections
	// are not tracked and will not be closed before method Run exits.
	Conns *ConnSet
	// Dialer should return a new connection to the provided address. It is
	// called on each new connection to an instance. net.Dial will be used if
	// left nil.
	Dialer func(net, addr string) (net.Conn, error)

	// RefreshCfgThrottle is the amount of time to wait between configuration
	// refreshes. If not set, it defaults to 1 minute.
	//
	// This is to prevent quota exhaustion in the case of client-side
	// malfunction.
	RefreshCfgThrottle time.Duration

	// The cfgCache holds the most recent connection configuration keyed by
	// instance. Relevant functions are refreshCfg and cachedCfg. It is
	// protected by cfgL.
	cfgCache map[string]cacheEntry
	cfgL     sync.RWMutex

	// MaxConnections is the maximum number of connections to establish
	// before refusing new connections. 0 means no limit.
	MaxConnections uint64

	// ConnectionsCounter is used to enforce the optional maxConnections limit
	ConnectionsCounter uint64
}

type cacheEntry struct {
	lastRefreshed time.Time
	// If err is not nil, the addr and cfg are not valid.
	err  error
	addr string
	cfg  *tls.Config
}

// Run causes the client to start waiting for new connections to connSrc and
// proxy them to the destination instance. It blocks until connSrc is closed.
func (c *Client) Run(connSrc <-chan Conn) {
	for conn := range connSrc {
		go c.handleConn(conn)
	}

	if err := c.Conns.Close(); err != nil {
		logging.Errorf("closing client had error: %v", err)
	}
}

func (c *Client) handleConn(conn Conn) {
	// This method handles incoming connections that then are proxied/dialled-out to the CloudSQL instance.
	ctx, _ := tag.New(context.Background(), tag.Insert(observability.KeyInstance, conn.Instance))
	// Track connections count only if a maximum connections limit is set to avoid useless overhead
	if c.MaxConnections > 0 {
		active := atomic.AddUint64(&c.ConnectionsCounter, 1)

		// Deferred decrement of ConnectionsCounter upon connection closing
		defer atomic.AddUint64(&c.ConnectionsCounter, ^uint64(0))

		if active > c.MaxConnections {
			ctx, _ = tag.New(ctx, tag.Upsert(observability.KeyReason, "too many connections"))
			stats.Record(ctx, observability.MErrors.M(1))
			logging.Errorf("too many open connections (max %d)", c.MaxConnections)
			conn.Conn.Close()
			return
		}
	}

	server, err := c.DialContext(ctx, conn.Instance)
	if err != nil {
		logging.Errorf("couldn't connect to %q: %v", conn.Instance, err)
		conn.Conn.Close()
		return
	}

	if false {
		// Log the connection's traffic via the debug connection if we're in a
		// verbose mode. Note that this is the unencrypted traffic stream.
		conn.Conn = dbgConn{conn.Conn}
	}

	c.Conns.Add(conn.Instance, conn.Conn)
	copyThenClose(server, conn.Conn, conn.Instance, "local connection on "+conn.Conn.LocalAddr().String())

	if err := c.Conns.Remove(conn.Instance, conn.Conn); err != nil {
		logging.Errorf("%s", err)
	}
}

// refreshCfg uses the CertSource inside the Client to find the instance's
// address as well as construct a new tls.Config to connect to the instance. It
// caches the result.
func (c *Client) refreshCfg(ctx context.Context, instance string) (addr string, cfg *tls.Config, err error) {
	startTime := time.Now()
	var remoteCertFetchDuration, localCertFetchDuration time.Duration

	c.cfgL.Lock()
	defer c.cfgL.Unlock()

	throttle := c.RefreshCfgThrottle
	if throttle == 0 {
		throttle = DefaultRefreshCfgThrottle
	}

	ctx, _ = tag.New(ctx, tag.Upsert(observability.KeyMethod, "refreshCfg"), tag.Upsert(observability.KeyPhase, "certRefresh"))
	var metrics []stats.Measurement

	defer func() {
		metrics = append(metrics, observability.MLatencyMs.M(observability.SinceInMilliseconds(startTime)))
		stats.Record(ctx, metrics...)

		// Now separately record the latencies for the two types of certificates' refresh latencies
		if remoteCertFetchDuration > 0 {
			rctx, _ := tag.New(ctx, tag.Upsert(observability.KeyCertType, "remote"))
			stats.Record(rctx, observability.MCertRefreshLatencyMs.M(observability.ToMilliseconds(remoteCertFetchDuration)))
		}
		if localCertFetchDuration > 0 {
			lctx, _ := tag.New(ctx, tag.Upsert(observability.KeyCertType, "local"))
			stats.Record(lctx, observability.MCertRefreshLatencyMs.M(observability.ToMilliseconds(localCertFetchDuration)))
		}
	}()

	if old := c.cfgCache[instance]; time.Since(old.lastRefreshed) < throttle {
		logging.Errorf("Throttling refreshCfg(%s): it was only called %v ago", instance, time.Since(old.lastRefreshed))
		// Refresh was called too recently, just reuse the result.
		ctx, _ = tag.New(ctx, tag.Upsert(observability.KeyConnectionState, "reused"), tag.Upsert(observability.KeyThrottled, "true"))
		return old.addr, old.cfg, old.err
	}

	if c.cfgCache == nil {
		c.cfgCache = make(map[string]cacheEntry)
	}

	defer func() {
		c.cfgCache[instance] = cacheEntry{
			lastRefreshed: time.Now(),

			err:  err,
			addr: addr,
			cfg:  cfg,
		}
	}()

	var mycert tls.Certificate
	localCertFetchDuration = timed(func() {
		mycert, err = c.Certs.Local(instance)
	})
	if err != nil {
		ctx, _ = tag.New(ctx, tag.Upsert(observability.KeyCertType, "local"), tag.Upsert(observability.KeyReason, err.Error()))
		metrics = append(metrics, observability.MErrors.M(1))
		return "", nil, err
	}

	var name string
	var scert *x509.Certificate
	remoteCertFetchDuration = timed(func() {
		scert, addr, name, err = c.Certs.Remote(instance)
	})
	if err != nil {
		ctx, _ = tag.New(ctx, tag.Upsert(observability.KeyCertType, "remote"), tag.Upsert(observability.KeyReason, err.Error()))
		metrics = append(metrics, observability.MErrors.M(1))
		return "", nil, err
	}
	certs := x509.NewCertPool()
	certs.AddCert(scert)
	// TODO: add the certificate type
	metrics = append(metrics, observability.MCertsAdded.M(1))

	cfg = &tls.Config{
		ServerName:   name,
		Certificates: []tls.Certificate{mycert},
		RootCAs:      certs,
		// We need to set InsecureSkipVerify to true due to
		// https://github.com/GoogleCloudPlatform/cloudsql-proxy/issues/194
		// https://tip.golang.org/doc/go1.11#crypto/x509
		//
		// Since we have a secure channel to the Cloud SQL API which we use to retrieve the
		// certificates, we instead need to implement our own VerifyPeerCertificate function
		// that will verify that the certificate is OK.
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: genVerifyPeerCertificateFunc(name, certs),
	}
	return fmt.Sprintf("%s:%d", addr, c.Port), cfg, nil
}

// genVerifyPeerCertificateFunc creates a VerifyPeerCertificate func that verifies that the peer
// certificate is in the cert pool. We need to define our own because of our sketchy non-standard
// CNs.
func genVerifyPeerCertificateFunc(instanceName string, pool *x509.CertPool) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("no certificate to verify")
		}

		cert, err := x509.ParseCertificate(rawCerts[0])
		if err != nil {
			return fmt.Errorf("x509.ParseCertificate(rawCerts[0]) returned error: %v", err)
		}

		opts := x509.VerifyOptions{Roots: pool}
		if _, err = cert.Verify(opts); err != nil {
			return err
		}

		if cert.Subject.CommonName != instanceName {
			return fmt.Errorf("certificate had CN %q, expected %q", cert.Subject.CommonName, instanceName)
		}
		return nil
	}
}

func timed(fn func()) time.Duration {
	start := time.Now()
	fn()
	return time.Since(start)
}

func (c *Client) cachedCfg(instance string) (string, *tls.Config) {
	c.cfgL.RLock()
	ret, ok := c.cfgCache[instance]
	c.cfgL.RUnlock()

	// Don't waste time returning an expired/invalid cert.
	if !ok || ret.err != nil || time.Now().After(ret.cfg.Certificates[0].Leaf.NotAfter) {
		return "", nil
	}
	return ret.addr, ret.cfg
}

// Dial uses the configuration stored in the client to connect to an instance.
// If this func returns a nil error the connection is correctly authenticated
// to connect to the instance.
func (c *Client) Dial(instance string) (net.Conn, error) {
	return c.DialContext(context.Background(), instance)
}

func (c *Client) DialContext(ctx context.Context, instance string) (net.Conn, error) {
	// Start tracing and metrics collection.
	ctx, _ = tag.New(ctx, tag.Upsert(observability.KeyInstance, instance), tag.Upsert(observability.KeyMethod, "dial"))
	ctx, span := trace.StartSpan(ctx, "proxy.(*Client).DialContext")

	metrics := make([]stats.Measurement, 0, 5)
	dialStartTime := time.Now()
	defer func() {
		mLatency := observability.MLatencyMs.M(observability.SinceInMilliseconds(dialStartTime))
		metrics = append(metrics, mLatency)
		stats.Record(ctx, metrics...)
		span.End()
	}()

	if addr, cfg := c.cachedCfg(instance); cfg != nil {
		ctx, ret, err := c.tryConnect(ctx, addr, cfg)
		if err == nil {
			ctx, _ = tag.New(ctx,
				tag.Upsert(observability.KeyConnectionState, "reused"),
				tag.Upsert(observability.KeyThrottled, "true"),
				tag.Upsert(observability.KeyStatus, "success"))

			metrics = append(metrics, observability.MOutboundConnections.M(1))
			return ret, nil
		} else {
			ctx, _ = tag.New(ctx,
				tag.Upsert(observability.KeyPhase, "cachedCfg"),
				tag.Upsert(observability.KeyReason, err.Error()),
				tag.Insert(observability.KeyStatus, "error"))

			metrics = append(metrics, observability.MErrors.M(1), observability.MOutboundConnections.M(1))
		}
	}

	addr, cfg, err := c.refreshCfg(ctx, instance)
	if err != nil {
		span.SetStatus(trace.Status{Code: trace.StatusCodeInternal, Message: err.Error()})
		return nil, err
	}

	var conn net.Conn
	ctx, conn, err = c.tryConnect(ctx, addr, cfg)
	if err == nil {
		ctx, _ = tag.New(ctx,
			tag.Upsert(observability.KeyConnectionState, "new"),
			tag.Upsert(observability.KeyStatus, "success"))

		metrics = append(metrics, observability.MOutboundConnections.M(1))
	} else {
		ctx, _ = tag.New(ctx,
			tag.Upsert(observability.KeyPhase, "tryConnect"),
			tag.Upsert(observability.KeyReason, err.Error()),
			tag.Insert(observability.KeyStatus, "error"))

		metrics = append(metrics, observability.MErrors.M(1), observability.MOutboundConnections.M(1))
		span.SetStatus(trace.Status{Code: trace.StatusCodeInternal, Message: err.Error()})
	}
	return conn, err
}

// tryConnect passes back the context as the first return value because it can add tags indictive
// of the phase that an error was encountered, without incrementing errors. This way its sole
// consumer chooses to deal with errors and can selectively handle errors.
func (c *Client) tryConnect(ctx context.Context, addr string, cfg *tls.Config) (context.Context, net.Conn, error) {
	d := c.Dialer
	if d == nil {
		d = net.Dial
	}
	conn, err := d("tcp", addr)
	if err != nil {
		return ctx, nil, err
	}
	type setKeepAliver interface {
		SetKeepAlive(keepalive bool) error
		SetKeepAlivePeriod(d time.Duration) error
	}

	if s, ok := conn.(setKeepAliver); ok {
		if err := s.SetKeepAlive(true); err != nil {
			ctx, _ = tag.New(ctx, tag.Upsert(observability.KeyType, "keepalive"))
			logging.Verbosef("Couldn't set KeepAlive to true: %v", err)
		} else if err := s.SetKeepAlivePeriod(keepAlivePeriod); err != nil {
			ctx, _ = tag.New(ctx, tag.Upsert(observability.KeyType, "keepalive_period"))
			logging.Verbosef("Couldn't set KeepAlivePeriod to %v", keepAlivePeriod)
		}
	} else {
		logging.Verbosef("KeepAlive not supported: long-running tcp connections may be killed by the OS.")
	}

	ret := tls.Client(conn, cfg)
	if err := ret.Handshake(); err != nil {
		ctx, _ = tag.New(ctx, tag.Upsert(observability.KeyType, "handshake"))
		ret.Close()
		return ctx, nil, err
	}
	return ctx, ret, nil
}

// NewConnSrc returns a chan which can be used to receive connections
// on the passed Listener. All requests sent to the returned chan will have the
// instance name provided here. The chan will be closed if the Listener returns
// an error.
func NewConnSrc(instance string, l net.Listener) <-chan Conn {
	// This method handles incoming connections that then are proxied/dialled-out to the CloudSQL instance.
	ch := make(chan Conn)
	go func() {

		for {
			start := time.Now()
			c, err := l.Accept()
			// We'll record the number of connections received, with status of either:
			//  * error
			//  * success

			ctx, _ := tag.New(context.Background(), tag.Insert(observability.KeyInstance, instance), tag.Insert(observability.KeyMethod, "listen"))

			if err != nil {
				logging.Errorf("listener (%#v) had error: %v", l, err)
				ctx_, _ := tag.New(ctx, tag.Insert(observability.KeyStatus, "error"))
				stats.Record(ctx, observability.MInboundConnections.M(1))
				if nerr, ok := err.(net.Error); ok && nerr.Temporary() {
					d := 10*time.Millisecond - time.Since(start)
					if d > 0 {
						time.Sleep(d)
					}
					ctx_, _ = tag.New(ctx_, tag.Upsert(observability.KeyType, "temporary"), tag.Upsert(observability.KeyReason, err.Error()))
					stats.Record(ctx_, observability.MErrors.M(1))
					continue
				}
				ctx_, _ = tag.New(ctx_, tag.Upsert(observability.KeyType, "permanent"), tag.Upsert(observability.KeyReason, err.Error()))
				stats.Record(ctx_, observability.MErrors.M(1))
				l.Close()
				close(ch)
				return
			} else {
				ch <- Conn{instance, c}
				ctx, _ = tag.New(ctx, tag.Insert(observability.KeyStatus, "success"))
				stats.Record(ctx, observability.MInboundConnections.M(1))
			}
		}
	}()
	return ch
}
