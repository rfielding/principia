package edge

import (
	"bufio"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"sync"
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
	// If we connect successfully, do the websocket headers to our volunteer
	secKey, err := e.wsConsumeHeaders(addr, url, dest_conn)
	if err != nil {
		dest_conn.Close()
		e.LogRet(w, http.StatusInternalServerError, err, "unable to setup websocket to volunteer %s: %v", addr, err)
		return
	}
	if e.DebugTunnelMessages {
		e.Logger.Debug("tunnel websocket to volunteer %s", addr)
	}
	// Hijack our incoming to transport the websocket across these
	wconn, rw, err := e.wsHijack(w, r, secKey)
	if err != nil {
		dest_conn.Close()
		e.LogRet(w, http.StatusInternalServerError, err, "unable to hijack connection: %v", err)
		return
	}
	if e.DebugTunnelMessages {
		e.Logger.Debug("transport websocket to volunteer: %s", addr)
	}
	e.wsTransport(rw, dest_conn)
	wconn.Close()
	dest_conn.Close()
}

func WsSecWebSocketKey() string {
	return base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%d", rand.Int())))
}

func WsSecWebSocketAccept(key string) string {
	uuid := "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	h := sha1.New()
	io.WriteString(h, key)
	io.WriteString(h, uuid)
	v := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(v[:])
}

// wsHijack should be called when we have header values set, and are
// ready to switch to a TCP socket
func (e *Edge) wsHijack(w http.ResponseWriter, r *http.Request, wsKey string) (net.Conn, *bufio.ReadWriter, error) {
	// Steal the writer body as a 2way socket
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("Unable to upgrade to websocket")
	}
	secAccept := WsSecWebSocketAccept(wsKey)
	w.Header().Set("Connection", "Upgrade")
	w.Header().Set("Upgrade", "websocket")
	w.Header().Set(
		"Sec-WebSocket-Accept",
		secAccept,
	)
	w.WriteHeader(101)
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		return nil, nil, fmt.Errorf("Unable to get client hijack: %v", err)
	}
	if e.DebugTunnelMessages {
		e.Logger.Debug("connection is hijacked")
	}
	return conn, rw, nil
}

// wsTransport will block until up and down are both drained
func (e *Edge) wsTransport(up *bufio.ReadWriter, down net.Conn) {
	downw := bufio.NewWriter(down)
	// Transport data between two points, and stall until it is done.
	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		buf := make([]byte, 1024)
		for {
			if e.DebugTunnelMessages {
				e.Logger.Debug("up read wait")
			}
			read, err := up.Read(buf)
			if err == io.EOF {
				break
			}
			if err != nil {
				e.Logger.Error("unable to read buf up: %v", err)
				break
			}
			//up.Flush()
			if e.DebugTunnelMessages {
				e.Logger.Debug("up read %d", read)
			}
			written, err := downw.Write(buf[0:read])
			if err != nil {
				e.Logger.Error("unable to write buffer down: %v", err)
			}
			if e.DebugTunnelMessages {
				e.Logger.Debug("down write %d", written)
			}
			downw.Flush()
		}
		//up.Flush()
		downw.Flush()
		if e.DebugTunnelMessages {
			e.Logger.Debug("down finished")
		}
		wg.Done()
	}()
	go func() {
		buf := make([]byte, 1024)
		for {
			if e.DebugTunnelMessages {
				e.Logger.Debug("down read wait")
			}
			read, err := down.Read(buf)
			if err == io.EOF {
				break
			}
			if err != nil {
				e.Logger.Error("unable to read buf down: %v", err)
				break
			}
			//downw.Flush()
			if e.DebugTunnelMessages {
				e.Logger.Debug("down read %d", read)
			}
			written, err := up.Write(buf[0:read])
			if err == io.EOF {
				break
			}
			if err != nil {
				e.Logger.Error("unable to write buffer up: %v", err)
				break
			}
			if e.DebugTunnelMessages {
				e.Logger.Debug("up write %d", written)
			}
			up.Flush()
		}
		up.Flush()
		if e.DebugTunnelMessages {
			e.Logger.Debug("up finished")
		}
		//downw.Flush()
		wg.Done()
	}()
	if e.DebugTunnelMessages {
		e.Logger.Debug("waiting on down writer")
	}
	wg.Wait()
	if e.DebugTunnelMessages {
		e.Logger.Debug("done waiting on down writer")
	}
}
