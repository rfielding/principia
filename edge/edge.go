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

	"github.com/rfielding/principia/auth"
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

// Command is the most important kind of Spawn
type Command struct {
	Cmd       []string
	Env       []string
	Dir       string
	Stdout    io.Writer
	Stderr    io.Writer
	Stdin     io.Reader
	Running   *exec.Cmd
	Server    *http.Server
	Override  func(spawn *Spawn)
	HttpCheck string
	SkipCheck bool
}

// Listener is a spawned process that exposes a port
// to be reachable within the network
// Listeners are removed when their Cmd dies
type Spawn struct {
	Owner *Edge
	// Almost always bound to 127.0.0.1:port
	Bind string
	Port Port
	// This is how we look up services, by name/instance
	Name       string
	Expose     bool
	KeepPrefix bool
	Run        Command
	// We can use this to have a port inserted upon spawn
	PortIntoCmdArg int
	PortIntoEnv    string
}

type Tunnel struct {
	Owner    *Edge
	Name     string
	Port     Port
	Listener net.Listener
}

func (t *Tunnel) Address() string {
	return fmt.Sprintf("%s:%d", t.Owner.HostSidecar, t.Port)
}

func (s *Spawn) Address() string {
	return fmt.Sprintf("%s:%d", s.Owner.HostSidecar, s.Port)
}

type IdentityFiles struct {
	CertPath  string
	KeyPath   string
	TrustPath string
}

// Edge is pointed to by Peer, and contains the reverse proxy to
// spawned Listener objects
type Edge struct {
	// The name is how reverse proxy binds and load balances us
	Name string
	// We can use a Host that will be NAT, as long as Port is same at NAT and inside.
	Host              string
	Port              Port
	Bind              string
	HostSidecar       string
	PortSidecar       Port
	BindSidecar       string
	Logger            common.Logger
	Spawns            []Spawn
	DefaultLease      time.Duration
	Peers             []Peer
	Tunnels           []Tunnel
	IdentityFiles     IdentityFiles
	HttpClient        *http.Client
	Trust             *auth.Trust
	TLSClientConfig   *tls.Config
	InternalServer    http.Server
	ExternalServer    http.Server
	Availability      *Availability
	AvailabilityLease time.Duration
	Done              chan bool
	HttpFilter        func(req *http.Request)
	Authenticator     *auth.Authenticator
	OAuthConfig       *auth.OAuthConfig
	LinkClaims        auth.LinkClaims
	DefaultURI        string
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
	return fmt.Sprintf("%s:%d", e.HostSidecar, e.PortSidecar)
}

func (e *Edge) AvailableFromPeer(peer Peer) (map[string]*Service, error) {
	j, err := e.GetFromPeer(peer.Name(), "/principia/available")
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
	spawns := e.Spawns
	for _, spawn := range spawns {
		available[spawn.Name] = &Service{
			Endpoint: fmt.Sprintf("%s:%d", e.HostSidecar, spawn.Port),
			Expose:   spawn.Expose,
		}
	}
	// These exist remotely
	tunnels := e.Tunnels
	for _, tunnel := range tunnels {
		available[tunnel.Name] = &Service{
			Endpoint:   fmt.Sprintf("%s:%d", e.HostSidecar, tunnel.Port),
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
							if services[kName].Expose {
								available[kName].Expose = true
							}
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
		ExpiresAt: time.Now().Add(e.AvailabilityLease),
	}
	return e.Availability
}

// Tells us to listen internally on a port
func (e *Edge) Exec(spawn Spawn) error {
	spawn.Owner = e
	if spawn.Name == "" {
		return fmt.Errorf("We must name spawned items")
	}
	spawnList := e.Spawns
	for i := range spawnList {
		if spawn.Name == spawnList[i].Name {
			return fmt.Errorf("Spawns must be uniquely within an edge.  You can make more edges on the same host.")
		}
	}
	if spawn.Port == 0 {
		spawn.Port = AllocPort()
	}
	if spawn.PortIntoCmdArg > 0 {
		spawn.Run.Cmd[spawn.PortIntoCmdArg] = spawn.Port.String()
	}
	if spawn.Bind == "" {
		spawn.Bind = e.BindSidecar
	}
	if spawn.Run.Stdout == nil {
		spawn.Run.Stdout = os.Stdout
	}
	if spawn.Run.Stderr == nil {
		spawn.Run.Stderr = os.Stderr
	}
	if spawn.Run.Stdin == nil {
		spawn.Run.Stdin = os.Stdin
	}
	if spawn.Run.Override != nil {
		spawn.Run.Override(&spawn)
	}
	e.Logger.Info("edge.Spawn: %s", common.AsJsonPretty(spawn))
	// Actually execute the command
	if len(spawn.Run.Cmd) > 0 {
		spawn.Run.Running = exec.Command(spawn.Run.Cmd[0], spawn.Run.Cmd[1:]...)
		spawn.Run.Running.Stdout = spawn.Run.Stdout
		spawn.Run.Running.Stderr = spawn.Run.Stderr
		spawn.Run.Running.Stdin = spawn.Run.Stdin
		spawn.Run.Running.Dir = spawn.Run.Dir
		commandFix(spawn.Run.Running)
		spawn.Run.Running.Env = append(
			os.Environ(),
			spawn.Run.Env...,
		)
		// By default, inject SIDECAR_INTERNAL to point to our sidecar
		spawn.Run.Running.Env = append(
			spawn.Run.Running.Env,
			fmt.Sprintf("SIDECAR_INTERNAL=%s", e.SidecarName()),
		)
		go func() {
			err := spawn.Run.Running.Run()
			if err != nil {
				e.Logger.Info("failed to spawn cmd %s for %v: %v", spawn.Run.Cmd, spawn.Port, err)
			}
			// When this spawn dies, remove it
			spawnList := e.Spawns
			for i := range spawnList {
				if spawn.Name == spawnList[i].Name {
					spawnList[i] = spawnList[len(spawnList)-1]
					spawnList = spawnList[0 : len(spawnList)-1]
					break
				}
			}
			e.Spawns = spawnList
		}()
	} else {
		if spawn.Run.Server != nil {
			bind := fmt.Sprintf("%s:%d", e.BindSidecar, spawn.Port)
			spawn.Run.Server.Addr = bind
			e.Logger.Info("spawn handler at http://%s", bind)
			go func() {
				err := spawn.Run.Server.ListenAndServe()
				if err != nil {
					e.Logger.Info("failed to run internal static file server for %s: %v", bind, err)
				}
			}()
		} else {
			return fmt.Errorf("Must specify a Run.Cmd, or a Run.Static")
		}
	}
	// Wait until the port is ready
	if !spawn.Run.SkipCheck {
		ready := make(chan bool)
		go func() {
			for {
				// If it isn't an http check, then at least do a TCP check
				if spawn.Run.HttpCheck == "" {
					conn, err := net.DialTimeout("tcp", spawn.Address(), time.Duration(1*time.Second))
					if err != nil {
						e.Logger.Info("%s wait 2 sec more", spawn.Address())
						time.Sleep(2 * time.Second)
						continue
					}
					conn.Close()
					ready <- true
					return
				}
				url := fmt.Sprintf("http://%s", spawn.Address())
				req, _ := http.NewRequest("GET", url, nil)
				cl := http.Client{}
				res, err := cl.Do(req)
				if err != nil {
					e.Logger.Info("%s wait 2 seco more", url)
					time.Sleep(2 * time.Second)
					continue
				}
				res.Body.Close()
				if res.StatusCode != 200 {
					continue
				}
				e.Logger.Info("%s is ready!", url)
				ready <- true
				return
			}
		}()
		_ = <-ready
	}

	e.Spawns = append(e.Spawns, spawn)
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
				return
			}
			e.wsTunnelTransport(tun_conn, service)
		}
	}()
	return nil
}

func (e *Edge) Close() error {
	e.Logger.Info("shutting down now!")
	tunnels := e.Tunnels
	for _, tunnel := range tunnels {
		if tunnel.Listener != nil {
			tunnel.Listener.Close()
		}
	}
	spawns := e.Spawns
	for _, spawn := range spawns {
		if spawn.Run.Running != nil {
			spawn.Run.Running.Process.Kill()
		}
		if spawn.Run.Server != nil {
			spawn.Run.Server.Shutdown(context.Background())
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
	if e.HostSidecar == "" {
		e.HostSidecar = "127.0.0.1"
	}
	if e.BindSidecar == "" {
		e.BindSidecar = "127.0.0.1"
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
	e.Trust = &auth.Trust{}
	e.Logger = common.NewLogger(fmt.Sprintf("%s", e.Name))
	e.Spawns = make([]Spawn, 0)
	e.Spawns = append(e.Spawns, Spawn{
		Bind: e.BindSidecar,
		Port: e.PortSidecar,
		Name: "sidecarInternal",
	})
	if e.DefaultLease == 0 {
		e.DefaultLease = time.Duration(30 * time.Second)
	}
	if e.AvailabilityLease == 0 {
		e.AvailabilityLease = time.Duration(5 * time.Second)
	}
	e.Peers = make([]Peer, 0)
	e.Tunnels = make([]Tunnel, 0)

	// Get the SystemCertPool, continue with an empty pool on error
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	// Read in the cert file
	certs, err := ioutil.ReadFile(e.IdentityFiles.TrustPath)
	if err != nil {
		e.Logger.Error("Failed to append %q to RootCAs: %v", e.IdentityFiles.TrustPath, err)
		return nil, err
	}
	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		e.Logger.Info("No certs appended, using system certs only")
	}
	certPem, err := ioutil.ReadFile(e.IdentityFiles.CertPath)
	if err != nil {
		return nil, err
	}
	keyPem, err := ioutil.ReadFile(e.IdentityFiles.KeyPath)
	if err != nil {
		return nil, err
	}
	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		return nil, err
	}

	issuers, err := e.Trust.TrustIssuers(certs)
	if err != nil {
		return nil, err
	}
	for _, iss := range issuers {
		e.Logger.Info("trusting: %s", iss.Name)
	}
	issuer, err := e.Trust.TrustIssuer(cert.Certificate[0], cert.PrivateKey)
	if err != nil {
		return nil, err
	}
	e.Logger.Info("trusting and can sign for: %s", issuer.Name)

	if e.OAuthConfig != nil {
		authenticator, err := auth.NewAuthenticator(
			e.OAuthConfig,
			e.Trust,
			e.Logger,
		)
		if err != nil {
			return nil, err
		}
		e.Authenticator = authenticator
		e.Logger.Info("OAuth configured to use provider %s", e.OAuthConfig.OAUTH2_PROVIDER)
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
	go e.ExternalServer.ListenAndServeTLS(
		e.IdentityFiles.CertPath,
		e.IdentityFiles.KeyPath,
	)

	// Our internal server can use plaintext
	e.InternalServer = http.Server{
		Addr:    fmt.Sprintf("%s:%d", e.BindSidecar, e.PortSidecar),
		Handler: e,
	}
	e.Logger.Info("edge.Start: http://%s:%d", e.HostSidecar, e.PortSidecar)
	go e.InternalServer.ListenAndServe()

	return e, nil
}
