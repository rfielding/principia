package edge

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

func (e *Edge) LogRet(w http.ResponseWriter, statusCode int, err error, msg string, args ...interface{}) error {
	e.Logger.Error(msg, args...)
	if err == nil {
		err = fmt.Errorf(fmt.Sprintf(msg, args...))
	}
	if w != nil {
		w.WriteHeader(statusCode)
	}
	return err
}

func (e *Edge) wsHttps(w http.ResponseWriter, r *http.Request, addr string, url string) {
	// Tunnel to the volunteer with a TLS cert
	dest_conn, err := tls.Dial("tcp", addr, e.TLSClientConfig)
	if err != nil {
		e.LogRet(w, http.StatusInternalServerError, err, "unable to dial volunteer: %v", err)
		return
	}
	defer dest_conn.Close()
	// If we connect successfully, do the websocket headers to our volunteer
	err = e.wsConsumeHeaders(addr, url, dest_conn)
	if err != nil {
		e.LogRet(w, http.StatusInternalServerError, err, "unable to setup websocket to volunteer %s: %v", addr, err)
		return
	}
	e.Logger.Debug("tunnel websocket to volunteer %s", addr)
	// Hijack our incoming to transport the websocket across these
	wconn, rw, err := e.wsHijack(w)
	if err != nil {
		e.LogRet(w, http.StatusInternalServerError, err, "unable to hijack connection: %v", err)
		return
	}
	defer wconn.Close()
	e.Logger.Debug("transport websocket to volunteer: %s", addr)
	e.wsTransport(rw, dest_conn)
}

// wsConsumeHeaders is used when we made a TCP connection to a socket
// which could be TLS or plaintext.  It strips the websocket headers off
// the front of the socket.  The url is used to locate the tunnel on the other end
// of the websocket.
func (e *Edge) wsConsumeHeaders(addr string, url string, conn net.Conn) error {
	if strings.HasPrefix(url, "http") {
		return fmt.Errorf("url includes address rather than just a full path: %s", url)
	}
	// Perform the websocket handshake, by writing the GET request on our tunnel
	conn.Write([]byte(fmt.Sprintf("GET %s HTTP/1.1\r\n", url)))
	conn.Write([]byte(fmt.Sprintf("Host: %s\r\n", addr)))
	conn.Write([]byte("Connection: Upgrade\r\n"))
	conn.Write([]byte("Upgrade: websocket\r\n"))
	conn.Write([]byte("\r\n"))

	// Consume the header that comes back, and ensure that it's a 101
	brdr := bufio.NewReader(conn)
	ln, _, err := brdr.ReadLine()
	line := string(ln)
	if err != nil {
		return e.LogRet(nil, 0, err, "failed to read line to %s: %v", url, err)
	}
	lineTokens := strings.Split(line, " ")
	if len(lineTokens) < 3 {
		return e.LogRet(nil, 0, nil, "malformed http response: %s", line)
	}
	if lineTokens[1] != "101" {
		return e.LogRet(nil, 0, nil, "wrong http error code: %s", line)
	}
	// Read lines until an empty one or error to consume the headers
	for {
		hdrLine, _, err := brdr.ReadLine()
		if err != nil {
			return e.LogRet(nil, 0, nil, "error reading headers: %v", err)
		}
		if len(hdrLine) == 0 {
			break
		}
	}
	return nil
}

// wsHijack should be called when we have header values set, and are
// ready to switch to a TCP socket
func (e *Edge) wsHijack(w http.ResponseWriter) (net.Conn, *bufio.ReadWriter, error) {
	// Steal the writer body as a 2way socket
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("Unable to upgrade to websocket")
	}
	w.Header().Set("Connection", "Upgrade")
	w.Header().Set("Upgrade", "websocket")
	w.WriteHeader(101)
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to get client hijack: %v", err)
	}
	e.Logger.Debug("connection is hijacked")
	return conn, rw, nil
}

// wsTransport will block until up and down are both drained
func (e *Edge) wsTransport(up *bufio.ReadWriter, down net.Conn) {
	// Transport data between two points, and stall until it is done.
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		buf := make([]byte, 1024)
		for {
			written, err := up.Read(buf)
			if err == io.EOF {
				up.Flush()
				break
			}
			if err != nil {
				e.Logger.Error("unable to read buf up: %v", err)
				break
			}
			written, err = down.Write(buf[0:written])
			if err != nil {
				e.Logger.Error("unable to write buffer down: %v", err)
			}
		}
		wg.Done()
	}()
	buf := make([]byte, 1024)
	for {
		written, err := down.Read(buf)
		if err == io.EOF {
			up.Flush()
			break
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			e.Logger.Error("unable to read buf down: %v", err)
			break
		}
		written, err = up.Write(buf[0:written])
		if err != nil {
			e.Logger.Error("unable to write buffer up: %v", err)
		}
		up.Flush()
	}
	wg.Wait()
}

// This is used from the plain TCP tunnel into the sidecar.  We must close the tunnel socket.
// This blocks until the tunnel is done.
func (e *Edge) wsTunnelTransport(tun_conn net.Conn, service string) {
	// Go does not have client-side hijacking, so we write the http request manually.
	defer tun_conn.Close()
	sidecar := e.SidecarName()
	sidecar_conn, err := net.DialTimeout(
		"tcp",
		sidecar,
		10*time.Second,
	)
	if err != nil {
		e.Logger.Error("tunnel unable to dial sidecar %s: %v", sidecar, err)
		return
	}
	defer sidecar_conn.Close()
	e.Logger.Debug("tunnel headers websocket to sidecar %s", sidecar)
	servicePrefix := fmt.Sprintf("/%s/", service)
	err = e.wsConsumeHeaders(sidecar, servicePrefix, sidecar_conn)
	if err != nil {
		sidecar_conn.Close()
		e.Logger.Error("tunnel unable to run websocket headers: %v", err)
		return
	}

	e.Logger.Debug("tunnel consuming websocket to sidecar %s", sidecar)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		io.Copy(tun_conn, sidecar_conn)
		wg.Done()
	}()
	io.Copy(sidecar_conn, tun_conn)
	wg.Wait()
	e.Logger.Debug("tunnel consumed websocket to sidecar %s", sidecar)
}
