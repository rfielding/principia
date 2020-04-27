package edge

import (
	"bufio"
	"fmt"
	"github.com/rfielding/principia/auth"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

func (e *Edge) Tunnel(service string, port Port) error {
	e.Logger.Info("e.Tunnel: %s %d", service, port)
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", e.HostSidecar, port))
	if err != nil {
		return err
	}
	tunnel := Tunnel{
		Owner:    e,
		Name:     service,
		Port:     port,
		Listener: listener,
	}
	e.Tunnels = append(e.Tunnels, tunnel)
	go func() {
		for {
			tun_conn, err := listener.Accept()
			if err != nil {
				e.Logger.Error("unable to spawn: %v", err)
				//continue
				// Assume that we only fail to Accept when listener dies
				continue
			}
			e.wsTunnelTransport(tun_conn, service)
			tun_conn.Close()
		}
	}()
	return nil
}

// This is used from the plain TCP tunnel into the sidecar.  We must close the tunnel socket.
// This blocks until the tunnel is done.
func (e *Edge) wsTunnelTransport(tun_conn net.Conn, service string) {
	// Go does not have client-side hijacking, so we write the http request manually.
	sidecar := e.SidecarName()
	sidecar_conn, err := net.DialTimeout(
		"tcp",
		sidecar,
		10*time.Second,
	)
	if err != nil {
		tun_conn.Close()
		e.Logger.Error("tunnel unable to dial sidecar %s: %v", sidecar, err)
		return
	}
	if e.DebugTunnelMessages {
		e.Logger.Debug("tunnel headers websocket to sidecar %s", sidecar)
	}
	servicePrefix := fmt.Sprintf("/%s/", service)
	_, err = e.wsConsumeHeaders(sidecar, servicePrefix, sidecar_conn)
	if err != nil {
		tun_conn.Close()
		sidecar_conn.Close()
		e.Logger.Error("tunnel unable to run websocket headers: %v", err)
		return
	}
	if e.DebugTunnelMessages {
		e.Logger.Debug("tunnel consuming websocket to sidecar %s", sidecar)
	}
	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		io.Copy(tun_conn, sidecar_conn)
		sidecar_conn.Close()
		tun_conn.Close()
		wg.Done()
	}()
	go func() {
		io.Copy(sidecar_conn, tun_conn)
		tun_conn.Close()
		sidecar_conn.Close()
		wg.Done()
	}()
	if e.DebugTunnelMessages {
		e.Logger.Debug("waiting for tunnel to consume websocket")
	}
	wg.Wait()
	if e.DebugTunnelMessages {
		e.Logger.Debug("tunnel consumed websocket to sidecar %s", sidecar)
	}
}

// wsConsumeHeaders is used when we made a TCP connection to a socket
// which could be TLS or plaintext.  It strips the websocket headers off
// the front of the socket.  The url is used to locate the tunnel on the other end
// of the websocket.
func (e *Edge) wsConsumeHeaders(addr string, url string, conn net.Conn) (string, error) {

	// Identify ourselves so that we can limit unexposed calls
	token, err := auth.Encode(
		auth.VerifiedClaims{
			Values: map[string][]string{
				"role": []string{"peer"},
			},
		},
		e.Trust,
	)
	if err != nil {
		return "", err
	}

	socketKey := WsSecWebSocketKey()
	secAccept := WsSecWebSocketAccept(socketKey)
	if strings.HasPrefix(url, "http") {
		return socketKey, fmt.Errorf("url includes address rather than just a full path: %s", url)
	}
	// Perform the websocket handshake, by writing the GET request on our tunnel
	conn.Write([]byte(fmt.Sprintf("GET %s HTTP/1.1\r\n", url)))
	conn.Write([]byte(fmt.Sprintf("Host: %s\r\n", addr)))
	conn.Write([]byte(fmt.Sprintf("Cookie: verified_claims=%s\r\n", token)))
	conn.Write([]byte("Connection: Upgrade\r\n"))
	conn.Write([]byte("Upgrade: websocket\r\n"))
	conn.Write([]byte(fmt.Sprintf("Sec-WebSocket-Key: %s\r\n", socketKey)))
	conn.Write([]byte("Sec-WebSocket-Protocol: chat, superchat\r\n"))
	conn.Write([]byte("Sec-WebSocket-Version: 13\r\n"))
	conn.Write([]byte("\r\n"))

	// Consume the header that comes back, and ensure that it's a 101
	brdr := bufio.NewReader(conn)
	ln, _, err := brdr.ReadLine()
	line := string(ln)
	if err != nil {
		return socketKey, e.LogRet(nil, 0, err, "failed to read line to %s: %v", url, err)
	}
	lineTokens := strings.Split(line, " ")
	if len(lineTokens) < 3 {
		return socketKey, e.LogRet(nil, 0, nil, "malformed http response: %s", line)
	}
	if lineTokens[1] != "101" {
		return socketKey, e.LogRet(nil, 0, nil, "wrong http error code: %s", line)
	}
	// Read lines until an empty one or error to consume the headers
	for {
		hdrLine, _, err := brdr.ReadLine()
		if err != nil {
			return socketKey, e.LogRet(nil, 0, nil, "error reading headers: %v", err)
		}
		if len(hdrLine) == 0 {
			break
		}
		tokens := strings.Split(string(hdrLine), ":")
		if len(tokens) > 2 {
			if strings.EqualFold(tokens[0], "Sec-WebSocket-Accept") {
				if secAccept != strings.TrimSpace(tokens[1]) {
					return socketKey, e.LogRet(nil, 0, nil, fmt.Sprintf("Sec-WebSocket-Accept wrong value: %s", secAccept))
				}
			}
		}
	}
	return socketKey, nil
}
