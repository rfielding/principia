package edge

import (
	"fmt"
	"github.com/rfielding/principia/common"
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
}

// ServeHTTP serves up http for this service
func (e *Edge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		if r.RequestURI == "/config" {
			w.Write(common.AsJsonPretty(e))
			return
		}
	}
}

// Tells us to listen internally on a port
func (e *Edge) Spawn(lsn Listener) error {
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
	//Use local Listeners or serve up peer Listeners
}

func AllocPort() int {
	p := nextPort
	nextPort++
	return p
}

func Start(e *Edge) *Edge {
	if e.Name != "" && e.Logger == nil {
		e.Logger = common.NewLogger(e.Name)
	}
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
	e.Listeners = make([]Listener, 0)
	e.DefaultLease = time.Duration(30 * time.Second)
	e.Peers = make([]Peer, 0)
	e.Logger("edge.Start: https://%s:%d", e.Host, e.Port)
	go http.ListenAndServe(fmt.Sprintf("%s:%d", e.Bind, e.Port), e)
	return e
}
