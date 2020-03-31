package edge

import (
	"encoding/json"
	"fmt"
	"github.com/rfielding/principia/common"
	"io/ioutil"
	"net"
	"net/http"
	"time"
)

var nextPort = 8022

// Peer is reached by an endpoint, and may contain Listeners
// that we can reach
// Peer is unreachable when expired, or consistently unreachable
type Peer struct {
	Host      string
	Port      int
	ExpiresAt time.Time
}

// Listener is a spawned process that exposes a port
// to be reachable within the network
// Listeners are removed when their Cmd dies
type Listener struct {
	// Almost always bound to 127.0.0.1:port
	Bind string
	Port int
	// This is how we look up services, by name/instance
	Name   string
	Expose bool
	Cmd    []string
	Env    []string
	// We can use this to have a port inserted upon spawn
	PortIntoCmdArg int
	PortIntoEnv    string
	Lsn            net.Listener
}

type Required struct {
	Name string
	Port int
}

// Edge is pointed to by Peer, and contains the reverse proxy to
// spawned Listener objects
type Edge struct {
	Name         string
	Host         string
	Bind         string
	Port         int
	Logger       common.Logger
	Listeners    []Listener
	DefaultLease time.Duration
	Peers        []Peer
	Required     []Required
}

type Item struct {
	Endpoint   string
	Volunteers []string
	Expose     bool
}

// TODO: upgrade all to https
func (e *Edge) AvailableFromPeer(peer Peer) map[string]*Item {
	url := fmt.Sprintf("http://%s:%d/available", peer.Host, peer.Port)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		e.Logger("error creating search %s for peer: %v", url, err)
		return nil
	}
	cl := http.Client{}
	res, err := cl.Do(req)
	if err != nil {
		e.Logger("error searching peer: %v", err)
		return nil
	}
	if res.StatusCode != http.StatusOK {
		e.Logger("error talking to %s peer: %d", url, res.StatusCode)
		res.Body.Close()
		return nil
	}
	j, err := ioutil.ReadAll(res.Body)
	if err != nil {
		e.Logger("unable to read body from %s: %v", url, err)
		res.Body.Close()
		return nil
	}
	res.Body.Close()
	var items map[string]*Item
	err = json.Unmarshal(j, &items)
	if err != nil {
		e.Logger("Unable to marshal response from %s: %v", url, err)
		return nil
	}
	return items
}

// Available should be periodically polled for
// ports available to service us
func (e *Edge) Available() map[string]*Item {
	available := make(map[string]*Item)
	// These are locally implemented
	for _, lsn := range e.Listeners {
		available[lsn.Name] = &Item{
			Endpoint: fmt.Sprintf("127.0.0.1:%d", lsn.Port),
			Expose:   lsn.Expose,
		}
	}
	// These exist remotely
	for _, rq := range e.Required {
		available[rq.Name] = &Item{
			Endpoint:   fmt.Sprintf("127.0.0.1:%d", rq.Port),
			Volunteers: make([]string, 0),
		}
	}
	// We narrow it down to which peers implement this
	for p, peer := range e.Peers {
		peerAddr := fmt.Sprintf("%s:%d", peer.Host, peer.Port)
		items := e.AvailableFromPeer(peer)
		if items == nil && time.Now().Unix() > e.Peers[p].ExpiresAt.Unix() {
			// it's expired and we could not contact it
		} else {
			if items != nil {
				e.Peers[p].ExpiresAt = time.Now().Add(e.DefaultLease)
				for kName, _ := range items {
					for _, rq := range e.Required {
						if kName == rq.Name {
							available[kName].Volunteers =
								append(
									available[kName].Volunteers,
									peerAddr,
								)
						}
					}
				}
			}
		}
	}
	// Sort peers by expiration time
	peerCount := len(e.Peers)
	now := time.Now()
	for i := 0; i < peerCount; i++ {
		for j := 0; j < peerCount; j++ {
			if e.Peers[i].ExpiresAt.Unix() > e.Peers[j].ExpiresAt.Unix() {
				tmp := e.Peers[i]
				e.Peers[i] = e.Peers[j]
				e.Peers[j] = tmp
			}
		}
	}
	// Cut off expired peers
	i := 0
	for i = 0; i < peerCount; i++ {
		if now.Unix() > e.Peers[i].ExpiresAt.Unix() {
			break
		}
	}
	e.Peers = e.Peers[0:i]

	return available
}

// ServeHTTP serves up http for this service
func (e *Edge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		if r.RequestURI == "/available" {
			w.Write(common.AsJsonPretty(e.Available()))
			return
		}
	}
}

// Tells us to listen internally on a port
func (e *Edge) Spawn(lsn Listener) error {
	if lsn.Name == "" {
		lsn.Name = e.Name
	}
	if lsn.Port == 0 {
		lsn.Port = AllocPort()
		if lsn.PortIntoCmdArg > 0 {
			lsn.Cmd[lsn.PortIntoCmdArg] = fmt.Sprintf("%d", lsn.Port)
		}
	}
	if lsn.Bind == "" {
		lsn.Bind = "127.0.0.1"
	}
	spawned, err := net.Listen("tcp", fmt.Sprintf("%s:%d", lsn.Bind, lsn.Port))
	if err != nil {
		return err
	}
	e.Logger("edge.Spawn: %s", common.AsJsonPretty(lsn))
	lsn.Lsn = spawned
	e.Listeners = append(e.Listeners, lsn)
	return nil
}

func (e *Edge) Peer(host string, port int) {
	e.Logger("edge.Peer: https://%s:%d", host, port)
	e.Peers = append(e.Peers, Peer{
		Host:      host,
		Port:      port,
		ExpiresAt: time.Now().Add(e.DefaultLease),
	})
}

func (e *Edge) Requires(listener string, port int) {
	e.Logger("e.Requires: %s %d", listener, port)
	e.Required = append(e.Required, Required{
		Name: listener,
		Port: port,
	})
}

func AllocPort() int {
	p := nextPort
	nextPort++
	return p
}

func Start(e *Edge) *Edge {
	// Allocate a port if not specified
	if e.Port == 0 {
		e.Port = AllocPort()
	}
	if e.Host == "" {
		e.Host = "127.0.0.1"
	}
	if e.Bind == "" {
		e.Bind = "0.0.0.0"
	}
	if e.Name != "" && e.Logger == nil {
		e.Logger = common.NewLogger(e.Name)
	}
	e.Listeners = make([]Listener, 0)
	e.DefaultLease = time.Duration(30 * time.Second)
	e.Peers = make([]Peer, 0)
	e.Required = make([]Required, 0)
	e.Logger("edge.Start: https://%s:%d", e.Host, e.Port)
	go http.ListenAndServe(fmt.Sprintf("%s:%d", e.Bind, e.Port), e)
	return e
}
