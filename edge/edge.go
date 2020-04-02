package edge

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/rfielding/principia/common"
	"io/ioutil"
	"net"
	"net/http"
	"time"
	"context"
)

var nextPort = 8022

type Port int

func (p Port) String() string {
	return fmt.Sprintf("%d", p)
}

// Peer is reached by an endpoint, and may contain Listeners
// that we can reach
// Peer is unreachable when expired, or consistently unreachable
type Peer struct {
	Host      string
	Port      Port
	ExpiresAt time.Time
}

// Listener is a spawned process that exposes a port
// to be reachable within the network
// Listeners are removed when their Cmd dies
type Listener struct {
	// Almost always bound to 127.0.0.1:port
	Bind string
	Port Port
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
	Port Port
}

// Edge is pointed to by Peer, and contains the reverse proxy to
// spawned Listener objects
type Edge struct {
	Name         string
	Host         string
	Bind         string
	Port         Port
	PortInternal Port
	Logger       common.Logger
	Listeners    []Listener
	DefaultLease time.Duration
	Peers        []Peer
	Required     []Required
	CertPath     string
	KeyPath      string
	TrustPath    string
	HttpClient *http.Client
	InternalServer http.Server
	ExternalServer http.Server
}

type Item struct {
	Endpoint   string
	Volunteers []string
	Expose     bool
}

func (e *Edge) GetFromPeer(peer Peer, cmd string) ([]byte,error) {
	url := fmt.Sprintf("https://%s:%d%s", peer.Host, peer.Port,cmd)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		e.Logger("error creating search %s for peer: %v", url, err)
		return nil,err
	}

	res, err := e.HttpClient.Do(req)
	if err != nil {
		e.Logger("error searching peer: %v", err)
		return nil,err
	}
	if res.StatusCode != http.StatusOK {
		res.Body.Close()
		return nil, fmt.Errorf("error talking to %s peer: %d", url, res.StatusCode)
	}
	j, err := ioutil.ReadAll(res.Body)
	return j,err
}

func (e *Edge) AvailableFromPeer(peer Peer) (map[string]*Item,error) {
	j, err := e.GetFromPeer(peer, "/available")
	if err != nil {
		return nil,err
	}
	var items map[string]*Item
	err = json.Unmarshal(j, &items)
	if err != nil {
		return nil, fmt.Errorf("Unable to marshal response from: %v", err)
	}
	return items,nil
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
		items, err := e.AvailableFromPeer(peer)
		if err != nil {
			e.Logger("peer unavailable: %v", err)
		}
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

func (e *Edge) Peer(host string, port Port) {
	e.Logger("edge.Peer: https://%s:%d", host, port)
	e.Peers = append(e.Peers, Peer{
		Host:      host,
		Port:      port,
		ExpiresAt: time.Now().Add(e.DefaultLease),
	})
}

func (e *Edge) Requires(listener string, port Port) {
	e.Logger("e.Requires: %s %d", listener, port)
	e.Required = append(e.Required, Required{
		Name: listener,
		Port: port,
	})
}

func AllocPort() Port {
	p := nextPort
	nextPort++
	return Port(p)
}

func (e *Edge) Close() error {
		for _,lsn := range e.Listeners {
			if lsn.Lsn != nil {
				lsn.Lsn.Close()
			}
		}
		e.ExternalServer.Shutdown(context.Background())
		e.InternalServer.Shutdown(context.Background())
		return nil
}


func Start(e *Edge) (*Edge,error) {
	// e.Port is an mTLS port that can talk to network
	// - runs our public handler
	if e.Port == 0 {
		e.Port = AllocPort()
	}
	// e.PortInternal is a plaintext port localhost only
	//- runs our public handler with private handling as well
	if e.PortInternal == 0 {
		e.PortInternal = AllocPort()
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

	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	// Read in the cert file
	certs, err := ioutil.ReadFile(e.TrustPath)
	if err != nil {
		e.Logger("Failed to append %q to RootCAs: %v", e.TrustPath, err)
		return nil, err
	}
	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		e.Logger("No certs appended, using system certs only")
	}
	certPem, err := ioutil.ReadFile(e.CertPath)
	if err != nil {
		return nil,err
	}
	keyPem, err := ioutil.ReadFile(e.KeyPath)
	if err != nil {
		return nil,err
	}
	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		return nil,err
	}

  // Create our client HttpConfig and transport
	e.HttpClient = &http.Client{
	  Transport: &http.Transport{
		  TLSClientConfig:&tls.Config{
				RootCAs:            rootCAs,
				InsecureSkipVerify: true, // This is not the same as skip verify, because of VerifyPeerCertificate!
				VerifyPeerCertificate: common.VerifyPeerCertificate,
				Certificates: []tls.Certificate{cert},
			},
		}	,
	}

  // Our external server needs TLS setup
	e.ExternalServer = http.Server{
		Addr: fmt.Sprintf("%s:%d", e.Bind, e.Port),
		Handler: e,
		TLSConfig: &tls.Config{
			RootCAs:            rootCAs,
			InsecureSkipVerify: true, // This is not the same as skip verify, because of VerifyPeerCertificate!
			VerifyPeerCertificate: common.VerifyPeerCertificate,
			Certificates: []tls.Certificate{cert},
		},
	}
	e.Logger("edge.Start: https://%s:%d", e.Host, e.Port)
  go e.ExternalServer.ListenAndServeTLS(e.CertPath, e.KeyPath)

	// Our internal server can use plaintext
	e.InternalServer = http.Server{
		Addr: fmt.Sprintf("127.0.0.1:%d", e.PortInternal),
		Handler: e,
	}
	e.Logger("edge.Start: http://127.0.0.1:%d", e.Host, e.PortInternal)
	go e.InternalServer.ListenAndServe()

	return e,nil
}
