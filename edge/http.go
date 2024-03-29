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

func (e *Edge) serveHTTPForVolunteer(w http.ResponseWriter, r *http.Request, canUseHidden bool, wantsWebsockets bool, service *Service) {
	if !canUseHidden && !service.Expose {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	volunteers := service.Volunteers
	// Pick a random volunteer
	if len(volunteers) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	rv := int(rand.Int31n(int32(len(volunteers))))
	volunteer := volunteers[rv]
	// We want exact same URI and headers, just different destination
	url := fmt.Sprintf("https://%s%s", volunteer, r.RequestURI)
	if e.DebugTunnelMessages {
		e.Logger.Debug("volunteer: %s %s -> %s", r.Method, url, volunteer)
	}
	req, err := http.NewRequest(r.Method, url, r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		msg := fmt.Sprintf("Failed To Create Request: %v", err)
		w.Write([]byte(msg))
		return
	}
	req.Header = r.Header.Clone()
	cl := e.HttpClient
	res, err := cl.Do(req)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		msg := fmt.Sprintf("Failed To Perform Request: %v", err)
		w.Write([]byte(msg))
		return
	}
	// Copy the body
	if wantsWebsockets {
		e.wsHttps(w, r, volunteer, r.RequestURI)
	} else {
		// Copy over the headers
		for k, a := range res.Header {
			for i := range a {
				w.Header().Add(k, a[i])
			}
		}
		// Copy the response code
		w.WriteHeader(res.StatusCode)
		io.Copy(w, res.Body)
		res.Body.Close()
	}
}

func (e *Edge) serveHTTPForSpawn(w http.ResponseWriter, r *http.Request, canUseHidden bool, wantsWebsockets bool, spawn Spawn) {

	if !canUseHidden && !spawn.Expose {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	to := fmt.Sprintf("%s:%d", e.HostSidecar, spawn.Port)
	if e.DebugTunnelMessages {
		e.Logger.Debug("listener: GET %s -> %s %s", r.RequestURI, spawn.Name, to)
	}

	if wantsWebsockets {

		// Dial the destination in plaintext, with no websocket headers
		dest_conn, err := net.DialTimeout("tcp", to, 10*time.Second)
		if err != nil {
			e.Logger.Error("unable to connect to %s: %v", to, err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		// If that worked, then hijack the connection incoming
		if e.DebugTunnelMessages {
			e.Logger.Debug("transporting websocket to service %s", to)
		}

		src_conn, rw, err := e.wsHijack(w, r, r.Header.Get("Sec-WebSocket-Key"))
		if err != nil {
			dest_conn.Close()
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		e.wsTransport(rw, dest_conn)
		src_conn.Close()
		dest_conn.Close()

	} else {

		path := "/" + r.RequestURI[2+len(spawn.Name):]
		if spawn.KeepPrefix {
			path = "/" + spawn.Name + path
		}

		url := fmt.Sprintf("http://%s%s", to, path)
		if e.DebugTunnelMessages {
			e.Logger.Debug("try %s", url)
		}

		req, err := http.NewRequest(r.Method, url, r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			msg := fmt.Sprintf("Failed To Create Request: %v", err)
			e.Logger.Error(msg)
			w.Write([]byte(msg))
			return
		}

		// Copy all headers into new request
		req.Header = r.Header.Clone()
		res, err := e.HttpClient.Do(req)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			msg := fmt.Sprintf("Failed To Perform Request: %v", err)
			w.Write([]byte(msg))
			return
		}

		// Copy over the headers
		for k, a := range res.Header {
			for i := range a {
				w.Header().Add(k, a[i])
			}
		}

		// Copy the response code
		w.WriteHeader(res.StatusCode)
		io.Copy(w, res.Body)
		res.Body.Close()
	}
}

func (e *Edge) findPrivileges(r *http.Request) (bool, auth.VerifiedClaims) {
	canUseHidden := false
	var err error
	var vc auth.VerifiedClaims
	vcCookie, err := r.Cookie("verified_claims")
	if err == nil {
		vc, err = auth.Decode([]byte(vcCookie.Value), e.Trust)
		if err != nil {
			e.Logger.Error("verified claims parse fail: %v", err)
		} else {
			// Claims have legitimate info in them
			canUseHidden =
				len(vc.Values) > 0 &&
					len(vc.Values["role"]) > 0 &&
					common.ArrayHas(vc.Values["role"], "peer")
		}
	} else {
		if e.DebugTunnelMessages {
			e.Logger.Debug("verified_claims cookie: %s... in %s", err, r.Header.Get("Cookie"))
		}
	}
	return canUseHidden, vc
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

	if e.DebugTunnelMessages {
		e.Logger.Debug("handling: %s", r.URL.Path)
	}

	if r.URL.Path == "/" && len(e.DefaultURI) > 0 {
		http.Redirect(w, r, e.DefaultURI, http.StatusFound)
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

	wantsWebsockets :=
		r.Header.Get("Connection") == "Upgrade" &&
			r.Header.Get("Upgrade") == "websocket"

	if e.DebugTunnelMessages {
		e.Logger.Debug("%s %s wantsWebsockets=%t", r.Method, r.RequestURI, wantsWebsockets)
	}

	canUseHidden, vc := e.findPrivileges(r)

	if len(vc.Email) > 0 {
		e.Logger.Info("visit by: %s", vc.Email)
	}

	// Find local spawns - we modify the url
	for _, spawn := range e.Spawns {
		if strings.HasPrefix(r.RequestURI, "/"+spawn.Name+"/") {
			e.serveHTTPForSpawn(w, r, canUseHidden, wantsWebsockets, spawn)
			return
		}
	}

	// XXX - I need to turn this off to use the actual oidc service.
	// Some bug with redirect is not getting same behavior, though forwarding
	// looks like it should be identical
	if true && e.Authenticator != nil && strings.HasPrefix(r.URL.Path, "/oidc/") {
		e.Authenticator.ServeHTTP(w, r)
		return
	}

	// Search volunteers - leave url alone
	for name := range available {
		service := available[name]
		if strings.HasPrefix(r.RequestURI, "/"+name+"/") {
			e.serveHTTPForVolunteer(w, r, canUseHidden, wantsWebsockets, service)
			return
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
