package edge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/rfielding/principia/common"
)

/*
   We begin allocating ports here, and just increment
*/
var StartPort = 8022

type Port int

func (p Port) String() string {
	return fmt.Sprintf("%d", p)
}

func AllocPort() Port {
	p := StartPort
	StartPort++
	return Port(p)
}

// Peer is reached by an endpoint, and may contain Listeners
// that we can reach
// Peer is unreachable when expired, or consistently unreachable
type Peer struct {
	Host      string
	Port      Port
	ExpiresAt time.Time
}

type Command struct {
	Cmd       []string
	Env       []string
	Dir       string
	Stdout    io.Writer
	Stderr    io.Writer
	Stdin     io.Reader
	Running   *exec.Cmd
	Static    string
	Server    *http.Server
	EditFn    func(lsn *Listener)
	HttpCheck string
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
	Run    Command
	// We can use this to have a port inserted upon spawn
	PortIntoCmdArg int
	PortIntoEnv    string
}

type Tunnel struct {
	Name     string
	Port     Port
	Listener net.Listener
}

// Edge is pointed to by Peer, and contains the reverse proxy to
// spawned Listener objects
type Edge struct {
	Name            string
	Host            string
	Bind            string
	Port            Port
	PortSidecar     Port
	Logger          common.Logger
	Listeners       []Listener
	DefaultLease    time.Duration
	Peers           []Peer
	Tunnels         []Tunnel
	CertPath        string
	KeyPath         string
	TrustPath       string
	HttpClient      *http.Client
	TLSClientConfig *tls.Config
	InternalServer  http.Server
	ExternalServer  http.Server
	Availability    *Availability
	Done            chan bool
}

type Service struct {
	Endpoint   string   `json:"Endpoint,omitempty"`
	Volunteers []string `json:"Volunteers,omitempty"`
	Expose     bool     `json:"Expose,omitempty"`
}

type Availability struct {
	ExpiresAt time.Time           `json:"ExpiresAt,omitempty"`
	Available map[string]*Service `json:"Available,omitempty"`
}

func (p Peer) Name() string {
	return fmt.Sprintf("%s:%d", p.Host, p.Port)
}

func (e *Edge) PeerName() string {
	return fmt.Sprintf("%s:%d", e.Host, e.Port)
}

func (e *Edge) SidecarName() string {
	return fmt.Sprintf("127.0.0.1:%d", e.PortSidecar)
}

func (e *Edge) AvailableFromPeer(peer Peer) (map[string]*Service, error) {
	j, err := e.GetFromPeer(peer.Name(), "/available")
	if err != nil {
		return nil, err
	}
	var services map[string]*Service
	err = json.Unmarshal(j, &services)
	if err != nil {
		return nil, fmt.Errorf("Unable to marshal response from: %v", err)
	}
	return services, nil
}

// Available should be periodically polled for
// ports available to service us
func (e *Edge) CheckAvailability() *Availability {
	if e.Availability != nil && e.Availability.ExpiresAt.Unix() > time.Now().Unix() {
		return e.Availability
	}
	logger := e.Logger.Push("Available")
	available := make(map[string]*Service)
	// These are locally implemented
	for _, lsn := range e.Listeners {
		available[lsn.Name] = &Service{
			Endpoint: fmt.Sprintf("127.0.0.1:%d", lsn.Port),
			Expose:   lsn.Expose,
		}
	}
	// These exist remotely
	for _, rq := range e.Tunnels {
		available[rq.Name] = &Service{
			Endpoint:   fmt.Sprintf("127.0.0.1:%d", rq.Port),
			Volunteers: make([]string, 0),
		}
	}
	// We narrow it down to which peers implement this
	for p, peer := range e.Peers {
		services, err := e.AvailableFromPeer(peer)
		if err != nil {
			logger.Error("peer unavailable: %v", err)
		}
		if services == nil && time.Now().Unix() > e.Peers[p].ExpiresAt.Unix() {
			// it's expired and we could not contact it
		} else {
			if services != nil {
				e.Peers[p].ExpiresAt = time.Now().Add(e.DefaultLease)
				for kName, _ := range services {
					for _, rq := range e.Tunnels {
						if kName == rq.Name {
							available[kName].Volunteers =
								append(
									available[kName].Volunteers,
									peer.Name(),
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
	e.Availability = &Availability{
		Available: available,
		ExpiresAt: time.Now().Add(5 * time.Second),
	}
	return e.Availability
}

// Tells us to listen internally on a port
func (e *Edge) Spawn(lsn Listener) error {
	if lsn.Name == "" {
		return fmt.Errorf("We must name spawned items")
	}
	if lsn.Port == 0 {
		lsn.Port = AllocPort()
	}
	if lsn.PortIntoCmdArg > 0 {
		lsn.Run.Cmd[lsn.PortIntoCmdArg] = lsn.Port.String()
	}
	if lsn.Bind == "" {
		lsn.Bind = "127.0.0.1"
	}
	if lsn.Run.Stdout == nil {
		lsn.Run.Stdout = os.Stdout
	}
	if lsn.Run.Stderr == nil {
		lsn.Run.Stderr = os.Stderr
	}
	if lsn.Run.Stdin == nil {
		lsn.Run.Stdin = os.Stdin
	}
	if lsn.Run.EditFn != nil {
		lsn.Run.EditFn(&lsn)
	}
	e.Logger.Info("edge.Spawn: %s", common.AsJsonPretty(lsn))
	// Actually execute the command
	if len(lsn.Run.Cmd) > 0 {
		lsn.Run.Running = exec.Command(lsn.Run.Cmd[0], lsn.Run.Cmd[1:]...)
		lsn.Run.Running.Stdout = lsn.Run.Stdout
		lsn.Run.Running.Stderr = lsn.Run.Stderr
		lsn.Run.Running.Stdin = lsn.Run.Stdin
		lsn.Run.Running.Dir = lsn.Run.Dir
		lsn.Run.Running.Env = append(os.Environ(), lsn.Run.Env...)
		go func() {
			err := lsn.Run.Running.Run()
			if err != nil {
				e.Logger.Info("failed to spawn cmd for %d: %v", lsn.Port, err)
			}
		}()
	} else {
		if len(lsn.Run.Static) > 0 {
			bind := fmt.Sprintf("127.0.0.1:%d", lsn.Port)
			e.Logger.Info("spawn static: http://%s vs %s", bind, lsn.Run.Static)
			lsn.Run.Server = &http.Server{
				Addr:    bind,
				Handler: http.FileServer(http.Dir(lsn.Run.Static)),
			}
			go func() {
				err := lsn.Run.Server.ListenAndServe()
				if err != nil {
					e.Logger.Info("failed to run internal static file server for %s: %v", bind, err)
				}
			}()
		} else {
			return fmt.Errorf("Must specify a Run.Cmd, or a Run.Static")
		}
	}
	// Wait until the port is ready
	ready := make(chan bool)
	go func() {
		for {
			if lsn.Run.HttpCheck == "" {
				ready <- true
				return
			}
			url := fmt.Sprintf("http://127.0.0.1:%d", lsn.Port)
			req, _ := http.NewRequest("GET", url, nil)
			cl := http.Client{}
			res, err := cl.Do(req)
			if err != nil {
				//e.Logger("not ready: %v", err)
				time.Sleep(1 * time.Second)
				continue
			}
			res.Body.Close()
			if res.StatusCode != 200 {
				continue
			}
			ready <- true
			return
		}
	}()
	_ = <-ready

	e.Listeners = append(e.Listeners, lsn)
	return nil
}

func (e *Edge) Peer(host string, port Port) {
	e.Logger.Info("edge.Peer: https://%s:%d", host, port)
	e.Peers = append(e.Peers, Peer{
		Host:      host,
		Port:      port,
		ExpiresAt: time.Now().Add(e.DefaultLease),
	})
}

func (e *Edge) Tunnel(service string, port Port) error {
	e.Logger.Info("e.Tunnel: %s %d", service, port)
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	tunnel := Tunnel{
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
				continue
			}
			e.wsTunnelTransport(tun_conn, service)
		}
	}()
	return nil
}

func (e *Edge) Close() error {
	if true {
		return nil
	}
	for _, tunnel := range e.Tunnels {
		if tunnel.Listener != nil {
			tunnel.Listener.Close()
		}
	}
	for _, lsn := range e.Listeners {
		if lsn.Run.Running != nil {
			lsn.Run.Running.Process.Kill()
		}
		if lsn.Run.Server != nil {
			lsn.Run.Server.Shutdown(context.Background())
		}
	}
	e.ExternalServer.Shutdown(context.Background())
	e.InternalServer.Shutdown(context.Background())
	e.Done <- true
	return nil
}

func Start(e *Edge) (*Edge, error) {
	e.Done = make(chan bool, 0)
	// e.Port is an mTLS port that can talk to network
	// - runs our public handler
	if e.Port == 0 {
		e.Port = AllocPort()
	}
	// a plaintext port localhost only
	//- runs our public handler with private handling as well
	if e.PortSidecar == 0 {
		e.PortSidecar = AllocPort()
	}
	if e.Host == "" {
		e.Host = "127.0.0.1"
	}
	if e.Bind == "" {
		e.Bind = "0.0.0.0"
	}
	if e.Name == "" {
		e.Name = fmt.Sprintf("%s:%d", e.Host, e.Port)
	}
	e.Logger = common.NewLogger(fmt.Sprintf("%s", e.Name))
	e.Listeners = make([]Listener, 0)
	e.Listeners = append(e.Listeners, Listener{
		Bind: "127.0.0.1",
		Port: e.PortSidecar,
		Name: "sidecarInternal",
	})

	e.DefaultLease = time.Duration(30 * time.Second)
	e.Peers = make([]Peer, 0)
	e.Tunnels = make([]Tunnel, 0)

	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	// Read in the cert file
	certs, err := ioutil.ReadFile(e.TrustPath)
	if err != nil {
		e.Logger.Error("Failed to append %q to RootCAs: %v", e.TrustPath, err)
		return nil, err
	}
	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		e.Logger.Info("No certs appended, using system certs only")
	}
	certPem, err := ioutil.ReadFile(e.CertPath)
	if err != nil {
		return nil, err
	}
	keyPem, err := ioutil.ReadFile(e.KeyPath)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		return nil, err
	}

	// Create our client HttpConfig and transport
	cfg := &tls.Config{
		RootCAs:               rootCAs,
		InsecureSkipVerify:    true, // This is not the same as skip verify, because of VerifyPeerCertificate!
		VerifyPeerCertificate: common.VerifyPeerCertificate,
		Certificates:          []tls.Certificate{cert},
	}
	e.TLSClientConfig = cfg
	e.HttpClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: cfg,
		},
	}

	// Our external server needs TLS setup
	e.ExternalServer = http.Server{
		Addr:    fmt.Sprintf("%s:%d", e.Bind, e.Port),
		Handler: e,
		TLSConfig: &tls.Config{
			RootCAs:               rootCAs,
			InsecureSkipVerify:    true, // This is not the same as skip verify, because of VerifyPeerCertificate!
			VerifyPeerCertificate: common.VerifyPeerCertificate,
			Certificates:          []tls.Certificate{cert},
		},
	}
	e.Logger.Info("edge.Start: https://%s:%d", e.Host, e.Port)
	go e.ExternalServer.ListenAndServeTLS(e.CertPath, e.KeyPath)

	// Our internal server can use plaintext
	e.InternalServer = http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", e.PortSidecar),
		Handler: e,
	}
	e.Logger.Info("edge.Start: http://127.0.0.1:%d", e.PortSidecar)
	go e.InternalServer.ListenAndServe()

	return e, nil
}
