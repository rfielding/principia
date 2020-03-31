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
	eAuth := edge.Start(&edge.Edge{
		Name: "eAuth",
	})
	TryTest(t, eAuth.Spawn(edge.Listener{
		PortIntoEnv: "EAUTH_PORT",
		Cmd:         []string{"/usr/bin/authsvr"},
	}))

	// This is a sidecar for a database on random port
	eDB := edge.Start(&edge.Edge{
		Name: "eDB_eWeb",
	})
	TryTest(t, eDB.Spawn(edge.Listener{
		PortIntoCmdArg: 2, // write into an arg
		Cmd:            []string{"/usr/bin/edb", "-p", "????", "-s", "eWeb"},
	}))

	// This is a proxy on 8122 to a web server on 8123, talking to db on
	eWeb := edge.Start(&edge.Edge{
		Name: "eWeb",
	})
	// Allocate an arbitrary port for the db
	eDB_eWeb_port := edge.AllocPort()
	eDB_eWeb_ports := fmt.Sprintf("%d", eDB_eWeb_port)
	eAuth_port := edge.AllocPort()
	eAuth_ports := fmt.Sprintf("%d", eAuth_port)
	// Spawn the web server talking to the db
	TryTest(t, eWeb.Spawn(edge.Listener{
		Expose:      true,
		Cmd:         []string{"/usr/bin/eWeb"},
		PortIntoEnv: "EWEB_PORT",
		Env: []string{
			"EDB_PORT", eDB_eWeb_ports,
			"EAUTH_PORT", eAuth_ports,
		},
	}))
	eWeb.Peer(eDB.Host, eDB.Port)
	eWeb.Peer(eAuth.Host, eAuth.Port)
	eWeb.Requires("eDB_eWeb", eDB_eWeb_port)
	eWeb.Requires("eAuth", eAuth_port)

	fmt.Printf("Available eAuth:%d %s", eAuth.Port, common.AsJsonPretty(eAuth.Available()))
	fmt.Printf("Available eDB:%d %s", eDB.Port, common.AsJsonPretty(eDB.Available()))
	fmt.Printf("Available eWeb:%d %s", eWeb.Port, common.AsJsonPretty(eWeb.Available()))
}
