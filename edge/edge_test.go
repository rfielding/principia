package edge_test

import (
	"fmt"
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

	// This is a sidecar for a database on random port
	eDB := edge.Start(&edge.Edge{
		Name: "proxy_eDB_eWeb",
	})
	TryTest(t, eDB.Spawn(edge.Listener{
		Name:           "eDB_eWeb",
		PortIntoCmdArg: 2,           // write into an arg
		PortIntoEnv:    "EWEB_PORT", // or write into an env
		Cmd:            []string{"/usr/bin/edb", "-p", "????", "-s", "eWeb"},
	}))

	// This is a proxy on 8122 to a web server on 8123, talking to db on
	eWeb := edge.Start(&edge.Edge{
		Name: "proxy_eWeb",
	})
	// Allocate an arbitrary port for the db
	eDB_eWeb_port := edge.AllocPort()
	eDB_eWeb_ports := fmt.Sprintf("%d", eDB_eWeb_port)
	// Spawn the web server talking to the db
	TryTest(t, eWeb.Spawn(edge.Listener{
		Name:           "eWeb",
		Expose:         true,
		PortIntoCmdArg: 2,
		Cmd:            []string{"/usr/bin/eWeb", "-p", "????", "-dbp", eDB_eWeb_ports},
		Env:            []string{"EWEB_PORT", eDB_eWeb_ports},
	}))
	eWeb.Peer(eDB.Host, eDB.Port)
	eWeb.Requires("eDB_eWeb", eDB_eWeb_port)
}
