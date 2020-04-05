package edge

import (
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/rfielding/principia/common"
)

// ServeHTTP serves up http for this service
func (e *Edge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logger := e.Logger.Push("ServeHTTP")
	// Find static items
	if r.Method == "GET" {
		if r.RequestURI == "/available" {
			w.Write(common.AsJsonPretty(e.Available()))
			return
		}
	}
	wantsWebsockets := r.Header.Get("Connection") == "Upgrade" &&
		r.Header.Get("Upgrade") == "websocket"
	logger.Info("%s %s wantsWebsockets=%t", r.Method, r.RequestURI, wantsWebsockets)

	// Find local listeners - we modify the url
	for _, lsn := range e.Listeners {
		if strings.HasPrefix(r.RequestURI, "/"+lsn.Name+"/") {
			to := fmt.Sprintf("127.0.0.1:%d", lsn.Port)
			logger.Info("listener: GET %s -> %s %s", r.RequestURI, lsn.Name, to)
			if wantsWebsockets {
				// Dial the destination in plaintext, with no websocket headers
				dest_conn, err := net.DialTimeout("tcp", to, 10*time.Second)
				if err != nil {
					e.Logger.Error("unable to connect to %s: %v", to, err)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				defer dest_conn.Close()
				// If that worked, then hijack the connection incoming
				e.Logger.Info("transporting websocket to service %s", to)
				src_conn, rw, err := e.wsHijack(w)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				defer src_conn.Close()
				e.wsTransport(rw, dest_conn)
			} else {
				path := "/" + r.RequestURI[2+len(lsn.Name):]
				url := fmt.Sprintf("http://%s%s", to, path)
				req, err := http.NewRequest(r.Method, url, r.Body)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					msg := fmt.Sprintf("Failed To Create Request: %v", err)
					logger.Error(msg)
					w.Write([]byte(msg))
					return
				}
				req.Header = r.Header
				res, err := e.HttpClient.Do(req)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					msg := fmt.Sprintf("Failed To Perform Request: %v", err)
					w.Write([]byte(msg))
					return
				}
				defer res.Body.Close()
				io.Copy(w, res.Body)
			}
			return
		}
	}
	// Search volunteers - leave url alone
	// Periodic poller start
	e.LastAvailable = e.Available()
	available := e.LastAvailable
	for name := range available {
		if strings.HasPrefix(r.RequestURI, "/"+name+"/") {
			volunteers := available[name].Volunteers
			// Pick a random volunteer
			if len(volunteers) > 0 {
				rv := int(rand.Int31n(int32(len(volunteers))))
				volunteer := volunteers[rv]
				url := fmt.Sprintf("https://%s%s", volunteer, r.RequestURI)
				logger.Info("volunteer: %s %s -> %s", r.Method, url, volunteer)
				req, err := http.NewRequest(r.Method, url, r.Body)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					msg := fmt.Sprintf("Failed To Create Request: %v", err)
					w.Write([]byte(msg))
					return
				}
				req.Header = r.Header
				cl := e.HttpClient
				res, err := cl.Do(req)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					msg := fmt.Sprintf("Failed To Perform Request: %v", err)
					w.Write([]byte(msg))
					return
				}
				if wantsWebsockets {
					e.wsHttps(w, r, volunteer, url)
				} else {
					io.Copy(w, res.Body)
				}
				return
			}
		}
	}
	w.WriteHeader(http.StatusNotFound)
}

func (e *Edge) GetFromPeer(peerName string, cmd string) ([]byte, error) {
	logger := e.Logger.Push("GetFromPeer")
	url := fmt.Sprintf("https://%s%s", peerName, cmd)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		logger.Error("error creating search %s for peer: %v", url, err)
		return nil, err
	}

	res, err := e.HttpClient.Do(req)
	if err != nil {
		logger.Error("error searching peer: %v", err)
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		res.Body.Close()
		return nil, fmt.Errorf("error talking to %s peer: %d", url, res.StatusCode)
	}
	j, err := ioutil.ReadAll(res.Body)
	return j, err
}
