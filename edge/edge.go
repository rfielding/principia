package edge

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
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

type Dependency struct {
	Name   string
	Port   Port
	Tunnel net.Listener
}

// Edge is pointed to by Peer, and contains the reverse proxy to
// spawned Listener objects
type Edge struct {
	Name            string
	Host            string
	Bind            string
	Port            Port
	PortInternal    Port
	Logger          common.Logger
	Listeners       []Listener
	DefaultLease    time.Duration
	Peers           []Peer
	Dependencies    []Dependency
	CertPath        string
	KeyPath         string
	TrustPath       string
	HttpClient      *http.Client
	TLSClientConfig *tls.Config
	InternalServer  http.Server
	ExternalServer  http.Server
	LastAvailable   map[string]*Service
	Done            chan bool
}

type Service struct {
	Endpoint   string   `json:"Endpoint,omitempty"`
	Volunteers []string `json:"Volunteers,omitempty"`
	Expose     bool     `json:"Expose,omitempty"`
}

func (p Peer) Name() string {
	return fmt.Sprintf("%s:%d", p.Host, p.Port)
}

func (e *Edge) PeerName() string {
	return fmt.Sprintf("%s:%d", e.Host, e.Port)
}

func (e *Edge) SidecarName() string {
	return fmt.Sprintf("127.0.0.1:%d", e.PortInternal)
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
func (e *Edge) Available() map[string]*Service {
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
	for _, rq := range e.Dependencies {
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
					for _, rq := range e.Dependencies {
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

	return available
}

func (e *Edge) LogRet(err error, msg string, args ...interface{}) error {
	e.Logger.Error(msg, args)
	if err == nil {
		return fmt.Errorf(fmt.Sprintf(msg, args...))
	}
	return err
}

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
				src_conn, err := e.wsHijack(w)
				if err != nil {
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				defer src_conn.Close()
				e.wsTransport(src_conn, dest_conn)
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
					e.wsHttps(w, r, url, volunteer)
				} else {
					io.Copy(w, res.Body)
				}
				return
			}
		}
	}
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

	// Periodic poller start
	e.LastAvailable = e.Available()
	return nil
}

func (e *Edge) Peer(host string, port Port) {
	e.Logger.Info("edge.Peer: https://%s:%d", host, port)
	e.Peers = append(e.Peers, Peer{
		Host:      host,
		Port:      port,
		ExpiresAt: time.Now().Add(e.DefaultLease),
	})
	// Periodic poller start
	e.LastAvailable = e.Available()
}

func (e *Edge) Dependency(service string, port Port) error {
	e.Logger.Info("e.Dependency: %s %d", service, port)
	tunnel, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	rq := Dependency{
		Name:   service,
		Port:   port,
		Tunnel: tunnel,
	}
	e.Dependencies = append(e.Dependencies, rq)
	go func() {
		for {
			tun_conn, err := tunnel.Accept()
			if err != nil {
				e.Logger.Error("unable to spawn: %v", err)
				continue
			}
			go e.wsDependencyTransport(tun_conn, service)
		}
	}()
	return nil
}

func (e *Edge) Close() error {
	for _, rq := range e.Dependencies {
		if rq.Tunnel != nil {
			rq.Tunnel.Close()
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
	if e.Name == "" {
		e.Name = fmt.Sprintf("%s:%d", e.Host, e.Port)
	}
	e.Logger = common.NewLogger(fmt.Sprintf("%s", e.Name))
	e.Listeners = make([]Listener, 0)
	e.Listeners = append(e.Listeners, Listener{
		Bind: "127.0.0.1",
		Port: e.PortInternal,
		Name: "sidecarInternal",
	})

	e.DefaultLease = time.Duration(30 * time.Second)
	e.Peers = make([]Peer, 0)
	e.Dependencies = make([]Dependency, 0)

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
		Addr:    fmt.Sprintf("127.0.0.1:%d", e.PortInternal),
		Handler: e,
	}
	e.Logger.Info("edge.Start: http://127.0.0.1:%d", e.PortInternal)
	go e.InternalServer.ListenAndServe()

	// Periodic poller start
	e.LastAvailable = e.Available()
	go func() {
		for {
			select {
			case <-e.Done:
				return
			case <-time.After(5 * time.Second):
				e.LastAvailable = e.Available()
			}
		}
	}()

	return e, nil
}
