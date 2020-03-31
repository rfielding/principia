package edge

import (
	"fmt"
	"github.com/rfielding/principia/common"
	"net/http"
	"time"
)

type Peer struct {
	Endpoint  string
	ExpiresAt time.Time
}

type Listener struct {
	// Almost always bound to 127.0.0.1:port
	Bind string
	Port int
	// This is how we look up services, by name/instance
	Name string
}

type Edge struct {
	Endpoint     string
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
		if r.RequestURI == "/listeners" {
			w.Write(common.AsJsonPretty(e.Listeners))
			return
		}
	}
}

// Tells us to listen internally on a port
func (e *Edge) Listen(lsn Listener) {
	if lsn.Bind == "" {
		lsn.Bind = "127.0.0.1"
	}
	e.Logger("edge.Listen: %s", common.AsJsonPretty(lsn))
	e.Listeners = append(e.Listeners, lsn)
}

func (e *Edge) Knows(endpoint string) {
	e.Logger("edge.Knows: %s", common.AsJsonPretty(endpoint))
	e.Peers = append(e.Peers, Peer{
		Endpoint:  endpoint,
		ExpiresAt: time.Now().Add(e.DefaultLease),
	})
}

func (e *Edge) Requires(listener string, port int) {
	e.Logger("e.Requires: %s %d", listener, port)
	//Use local Listeners or serve up peer Listeners
}

func Start(addr string, port int, logger common.Logger) *Edge {
	e := &Edge{
		Logger:       logger,
		Port:         port,
		Bind:         "0.0.0.0",
		Listeners:    make([]Listener, 0),
		DefaultLease: time.Duration(30 * time.Second),
		Peers:        make([]Peer, 0),
		Endpoint:     fmt.Sprintf("http://%s:%d", addr, port),
	}
	logger("edge.Start: %s", e.Endpoint)
	go http.ListenAndServe(fmt.Sprintf("0.0.0.0:%d", e.Port), e)
	return e
}
