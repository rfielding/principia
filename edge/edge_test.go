package edge_test

import (
	"fmt"
	"github.com/rfielding/principia/common"
	"github.com/rfielding/principia/edge"
	"testing"
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

	eAuth, err := edge.Start(&edge.Edge{
		Name:      "eAuth",
		CertPath:  certPath,
		KeyPath:   keyPath,
		TrustPath: trustPath,
	})
	TryTest(t, err)
	defer eAuth.Close()

	TryTest(t, eAuth.Spawn(edge.Listener{
		PortIntoEnv: "EAUTH_PORT",
		Cmd:         []string{"/usr/bin/authsvr"},
	}))

	eAuth2, err := edge.Start(&edge.Edge{
		Name:      "eAuth",
		CertPath:  certPath,
		KeyPath:   keyPath,
		TrustPath: trustPath,
	})
	TryTest(t, err)
	defer eAuth2.Close()

	TryTest(t, eAuth2.Spawn(edge.Listener{
		PortIntoEnv: "EAUTH_PORT",
		Cmd:         []string{"/usr/bin/authsvr"},
	}))

	// This is a sidecar for a database on random port
	eDB, err := edge.Start(&edge.Edge{
		Name:      "eDB_eWeb",
		CertPath:  certPath,
		KeyPath:   keyPath,
		TrustPath: trustPath,
	})
	TryTest(t, err)
	defer eDB.Close()

	TryTest(t, eDB.Spawn(edge.Listener{
		PortIntoCmdArg: 2, // write into an arg
		Cmd:            []string{"/usr/bin/edb", "-p", "????", "-s", "eWeb"},
	}))

	// This is a proxy on 8122 to a web server on 8123, talking to db on
	eWeb, err := edge.Start(&edge.Edge{
		Name:      "eWeb",
		CertPath:  certPath,
		KeyPath:   keyPath,
		TrustPath: trustPath,
	})
	TryTest(t, err)
	defer eWeb.Close()

	// Allocate an arbitrary port for the db
	eDB_eWeb_port := edge.AllocPort()
	eAuth_port := edge.AllocPort()

	// Spawn the web server talking to the db
	TryTest(t, eWeb.Spawn(edge.Listener{
		Expose:      true,
		Cmd:         []string{"/usr/bin/eWeb"},
		PortIntoEnv: "EWEB_PORT",
		Env: []string{
			"EDB_PORT", eDB_eWeb_port.String(),
			"EAUTH_PORT", eAuth_port.String(),
		},
	}))
	eWeb.Peer(eDB.Host, eDB.Port)
	eWeb.Peer(eAuth.Host, eAuth.Port)
	eWeb.Requires("eDB_eWeb", eDB_eWeb_port)
	eWeb.Requires("eAuth", eAuth_port)

	// Log info about it
	fmt.Printf("Available eAuth:%d %s\n", eAuth.Port, common.AsJsonPretty(eAuth.Available()))
	fmt.Printf("Available eDB:%d %s\n", eDB.Port, common.AsJsonPretty(eDB.Available()))
	fmt.Printf("Available eWeb:%d %s\n", eWeb.Port, common.AsJsonPretty(eWeb.Available()))

	eWeb_data, err := eWeb.GetFromPeer(eWeb.PeerName(), "/"+eWeb.Name+"/hello")
	TryTest(t, err)
	fmt.Printf("Got: %s\n", eWeb_data)

	eDB_eWeb_data, err := eWeb.GetFromPeer(eWeb.PeerName(), "/"+eWeb.Required[0].Name+"/hello")
	TryTest(t, err)
	fmt.Printf("Got: %s\n", eDB_eWeb_data)
}
