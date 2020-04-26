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

	"github.com/rfielding/principia/auth"
	"github.com/rfielding/principia/common"
)

// Put this in as a test
func (e *Edge) Echo(w http.ResponseWriter, r *http.Request) {
	closer, rw, err := e.wsHijack(w, r, r.Header.Get("Sec-WebSocket-Key"))
	if err != nil {
		w.WriteHeader(500)
		return
	}
	i := 0
	for {
		rw.ReadLine()
		rw.WriteString(fmt.Sprintf("%d\n", i))
		rw.Flush()
		time.Sleep(1 * time.Second)
		i++
	}
	closer.Close()
}

// ServeHTTP serves up http for this service
func (e *Edge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if e.HttpFilter != nil {
		e.HttpFilter(r)
	}
	if strings.HasPrefix(r.RequestURI, "http") {
		e.LogRet(w, http.StatusBadRequest, nil, "A requestURL must be a fully qualified path, not %s", r.RequestURI)
		return
	}
	e.Logger.Info("handling: %s", r.URL.Path)

	if r.URL.Path == "/" && len(e.DefaultURI) > 0 {
		http.Redirect(w, r, e.DefaultURI, http.StatusFound)
	}

	if true && e.Authenticator != nil && strings.HasPrefix(r.URL.Path, "/oidc") {
		e.Authenticator.ServeHTTP(w, r)
		return
	}

	available := e.CheckAvailability().Available
	// Find static items
	if r.Method == "GET" {
		if r.RequestURI == "/principia/echo" {
			e.Echo(w, r)
			return
		}
		if r.RequestURI == "/principia/available" {
			w.Write(common.AsJsonPretty(available))
			return
		}
		if r.RequestURI == "/principia/peers" {
			w.Write(common.AsJsonPretty(e.Peers))
			return
		}
	}

	wantsWebsockets := r.Header.Get("Connection") == "Upgrade" &&
		r.Header.Get("Upgrade") == "websocket"
	e.Logger.Debug("%s %s wantsWebsockets=%t", r.Method, r.RequestURI, wantsWebsockets)

	// Find local spawns - we modify the url
	for _, spawn := range e.Spawns {
		expectedServicePrefix := fmt.Sprintf("/%s/", spawn.Name)
		if strings.HasPrefix(r.RequestURI, expectedServicePrefix) {
			to := fmt.Sprintf("%s:%d", e.HostSidecar, spawn.Port)
			e.Logger.Debug("listener: GET %s -> %s %s", r.RequestURI, spawn.Name, to)
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
				e.Logger.Debug("transporting websocket to service %s", to)
				src_conn, rw, err := e.wsHijack(w, r, r.Header.Get("Sec-WebSocket-Key"))
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				defer src_conn.Close()
				e.wsTransport(rw, dest_conn)
			} else {
				path := "/" + r.RequestURI[2+len(spawn.Name):]
				if spawn.KeepPrefix {
					path = "/" + spawn.Name + path
				}
				url := fmt.Sprintf("http://%s%s", to, path)
				e.Logger.Info("try %s", url)
				req, err := http.NewRequest(r.Method, url, r.Body)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					msg := fmt.Sprintf("Failed To Create Request: %v", err)
					e.Logger.Error(msg)
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
	for name := range available {
		if strings.HasPrefix(r.RequestURI, "/"+name+"/") {
			volunteers := available[name].Volunteers
			// Pick a random volunteer
			if len(volunteers) > 0 {
				rv := int(rand.Int31n(int32(len(volunteers))))
				volunteer := volunteers[rv]
				url := fmt.Sprintf("https://%s%s", volunteer, r.RequestURI)
				e.Logger.Debug("volunteer: %s %s -> %s", r.Method, url, volunteer)
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
					e.wsHttps(w, r, volunteer, r.RequestURI)
				} else {
					io.Copy(w, res.Body)
				}
				return
			}
		}
	}
	e.LogRet(w, http.StatusNotFound, nil, "could not find: %s %s, have %s", r.Method, r.RequestURI, common.AsJsonPretty(available))
}

func (e *Edge) GetFromPeer(peerName string, cmd string) ([]byte, error) {
	token, err := auth.Encode(
		auth.VerifiedClaims{
			Values: map[string][]string{
				"role": []string{"peer"},
			},
		},
		e.Trust,
	)
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("https://%s%s", peerName, cmd)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		e.Logger.Error("error creating search %s for peer: %v", url, err)
		return nil, err
	}
	req.AddCookie(
		&http.Cookie{
			Name:  "verified_claims",
			Value: token,
		},
	)

	res, err := e.HttpClient.Do(req)
	if err != nil {
		e.Logger.Error("error searching peer: %v", err)
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		res.Body.Close()
		return nil, fmt.Errorf("error talking to %s peer: %d", url, res.StatusCode)
	}
	j, err := ioutil.ReadAll(res.Body)
	return j, err
}
