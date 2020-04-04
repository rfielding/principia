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

func (e *Edge) wsHttps(w http.ResponseWriter, r *http.Request, url string, volunteer string) {
	// Tunnel to the volunteer with a TLS cert
	dest_conn, err := tls.Dial("tcp", volunteer, e.TLSClientConfig)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		e.Logger.Error("unable to dial volunteer: %v", err)
		return
	}
	defer dest_conn.Close()
	// If we connect successfully, do the websocket headers to our volunteer
	err = e.wsConsumeHeaders(volunteer, url, dest_conn)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		e.Logger.Error("unable to setup websocket to volunteer %s: %v", volunteer, err)
		return
	}
	e.Logger.Info("prologue websocket to volunteer %s", volunteer)
	// Hijack our incoming to transport the websocket across these
	src_conn, err := e.wsHijack(w)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		e.Logger.Error("unable to hijack connection: %v", err)
		return
	}
	defer src_conn.Close()
	e.Logger.Info("transport websocket to volunteer: %s", volunteer)
	e.wsTransport(src_conn, dest_conn)
}

// wsConsumeHeaders is used when we made a TCP connection to a socket
// which could be TLS or plaintext.  It strips the websocket headers off
// the front of the socket.  The url is used to locate the tunnel on the other end
// of the websocket.
func (e *Edge) wsConsumeHeaders(host string, url string, conn net.Conn) error {
	// Perform the websocket handshake, by writing the GET request on our tunnel
	conn.Write([]byte(fmt.Sprintf("GET %s HTTP/1.1\r\n", url)))
	conn.Write([]byte(fmt.Sprintf("Host: %s\r\n", host)))
	conn.Write([]byte("Connection: Upgrade\r\n"))
	conn.Write([]byte("Upgrade: websocket\r\n"))
	conn.Write([]byte("\r\n"))

	// Consume the header that comes back, and ensure that it's a 101
	brdr := bufio.NewReader(conn)
	line, _, err := brdr.ReadLine()
	if err != nil {
		return e.LogRet(err, "failed to read line to %s: %v", url, err)
	}
	lineTokens := strings.Split(string(line), " ")
	if len(lineTokens) < 3 {
		return e.LogRet(nil, "malformed http response: %s", line)
	}
	if lineTokens[1] != "101" {
		return e.LogRet(nil, "wrong http error code: %s %s", lineTokens[0], lineTokens[1])
	}
	// Read lines until an empty one or error to consume the headers
	for {
		hdrLine, _, err := brdr.ReadLine()
		if err != nil {
			return e.LogRet(nil, "error reading headers: %v", err)
		}
		if len(hdrLine) == 0 {
			break
		}
	}
	return nil
}

// wsHijack should be called when we have header values set, and are
// ready to switch to a TCP socket
func (e *Edge) wsHijack(w http.ResponseWriter) (net.Conn, error) {
	// Steal the writer body as a 2way socket
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return nil, fmt.Errorf("Unable to upgrade to websocket")
	}
	w.Header().Set("Connection", "Upgrade")
	w.Header().Set("Upgrade", "websocket")
	w.WriteHeader(101)
	conn, _, err := hijacker.Hijack()
	if err != nil {
		return nil, fmt.Errorf("Unable to get client hijack: %v", err)
	}
	return conn, nil
}

// wsTransport will block until up and down are both drained
func (e *Edge) wsTransport(up_conn net.Conn, down_conn net.Conn) {
	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		io.Copy(up_conn, down_conn)
		wg.Done()
	}()
	go func() {
		io.Copy(up_conn, down_conn)
		wg.Done()
	}()
	e.Logger.Info("transport underway")
	wg.Wait()
	e.Logger.Info("transport done")
}

// This is used from the plain TCP tunnel into the sidecar.  We must close the tunnel socket.
// This blocks until the tunnel is done.
func (e *Edge) wsDependencyTransport(tun_conn net.Conn, service string) {
	defer tun_conn.Close()
	sidecar := e.SidecarName()
	dest_conn, err := net.DialTimeout(
		"tcp",
		sidecar,
		10*time.Second,
	)
	if err != nil {
		tun_conn.Close()
		e.Logger.Error("dependency unable to dial sidecar %s: %v", sidecar, err)
		return
	}
	defer dest_conn.Close()
	e.Logger.Info("dependency prologue websocket to sidecar %s", sidecar)
	err = e.wsConsumeHeaders(sidecar, "/"+service+"/", dest_conn)
	if err != nil {
		tun_conn.Close()
		dest_conn.Close()
		e.Logger.Error("dependency unable to run prologue: %v", err)
		return
	}
	e.Logger.Info("dependency consuming websocket to sidecar %s", sidecar)

	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		io.Copy(tun_conn, dest_conn)
		wg.Done()
	}()
	go func() {
		io.Copy(dest_conn, tun_conn)
		wg.Done()
	}()
	wg.Wait()
}
