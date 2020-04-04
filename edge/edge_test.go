package edge_test

import (
	"fmt"
	"github.com/rfielding/principia/common"
	"github.com/rfielding/principia/edge"
	"io/ioutil"
	"testing"
	"time"
)

func TryTest(t *testing.T, err error) {
	if err != nil {
		t.Logf("Failed test: %v", err)
		t.FailNow()
	}
}

func TestEdge(t *testing.T) {
	// can be per-identity, must be signed by trustPath
	certPath := "./test_cert.pem"
	keyPath := "./test_key.pem"
	// every peer trusts trustPath certs
	trustPath := "./test_cert.pem"

	/**
	Spawn a bunch of Edge machines.  They are
	effectively identical.
	*/

	// This is a sidecar for a database on random port
	eDB, err := edge.Start(&edge.Edge{
		CertPath:  certPath,
		KeyPath:   keyPath,
		TrustPath: trustPath,
	})
	TryTest(t, err)
	defer eDB.Close()

	eAuth, err := edge.Start(&edge.Edge{
		CertPath:  certPath,
		KeyPath:   keyPath,
		TrustPath: trustPath,
	})
	TryTest(t, err)
	defer eAuth.Close()

	eAuth2, err := edge.Start(&edge.Edge{
		CertPath:  certPath,
		KeyPath:   keyPath,
		TrustPath: trustPath,
	})
	TryTest(t, err)
	defer eAuth2.Close()

	// This is a proxy on 8122 to a web server on 8123, talking to db on
	eWeb, err := edge.Start(&edge.Edge{
		Port:      9022,
		Host:      "localhost",
		CertPath:  certPath,
		KeyPath:   keyPath,
		TrustPath: trustPath,
	})
	TryTest(t, err)
	defer eWeb.Close()

	/*
		  In the edge machines, we should spawn some commands.
			TODO: wait until port can be reached
	*/

	TryTest(t, eDB.Spawn(edge.Listener{
		Name: "eDB_eWeb",
		Run: edge.Command{
			EditFn: func(lsn *edge.Listener) {
				lsn.Run.Cmd[5] = fmt.Sprintf("127.0.0.1:%d:5984", lsn.Port)
			},
			Stdout: ioutil.Discard,
			Stderr: ioutil.Discard,
			Cmd: []string{
				"docker",
				"run",
				"--name", "eDB",
				"-p", "127.0.0.1:5984:5984",
				"-e", "COUCHDB_USER=admin",
				"-e", "COUCHDB_PASSWORD=password",
				"couchdb",
			},
			Dir: ".",
		},
	}))
	fmt.Printf("Available eDB:%d %s\n", eDB.Port, common.AsJsonPretty(eDB.Available()))

	TryTest(t, eAuth.Spawn(edge.Listener{
		Name:        "eAuth",
		PortIntoEnv: "EAUTH_PORT",
		Run: edge.Command{
			Cmd: []string{"tree"},
		},
	}))

	TryTest(t, eAuth2.Spawn(edge.Listener{
		Name:        "eAuth",
		PortIntoEnv: "EAUTH_PORT",
		Run: edge.Command{
			Cmd: []string{"ls", "-al"},
		},
	}))

	// Spawn the web server talking to the db
	TryTest(t, eWeb.Spawn(edge.Listener{
		Name:   "eWeb",
		Expose: true,
		Run: edge.Command{
			Static: ".",
		},
	}))

	time.Sleep(10 * time.Second)

	// Allocate an arbitrary port for the db
	eDB_eWeb_port := edge.AllocPort()
	eAuth_port := edge.AllocPort()
	eWeb.Peer(eDB.Host, eDB.Port)
	eWeb.Peer(eAuth.Host, eAuth.Port)
	eWeb.Peer(eAuth2.Host, eAuth.Port)
	eWeb.Requires("eDB_eWeb", eDB_eWeb_port)
	eWeb.Requires("eAuth", eAuth_port)

	// Log info about it
	fmt.Printf("Available eAuth:%d %s\n", eAuth.Port, common.AsJsonPretty(eAuth.Available()))
	fmt.Printf("Available eWeb:%d %s\n", eWeb.Port, common.AsJsonPretty(eWeb.Available()))

	eDB_eWeb_data, err := eDB.GetFromPeer(eWeb.PeerName(), "/eDB_eWeb/")
	TryTest(t, err)
	fmt.Printf("Got: %s\n", eDB_eWeb_data)

	eWeb_data, err := eWeb.GetFromPeer(eWeb.PeerName(), "/eDB_eWeb/")
	TryTest(t, err)
	fmt.Printf("Got: %s\n", eWeb_data)

	eWeb_data2, err := eWeb.GetFromPeer(eWeb.PeerName(), "/eWeb/")
	TryTest(t, err)
	fmt.Printf("Got: %s\n", eWeb_data2)

	fmt.Printf("https://%s/eWeb/", eWeb.PeerName())
	time.Sleep(5 * time.Minute)
}
