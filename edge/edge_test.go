package edge_test

import (
	"github.com/rfielding/principia/common"
	"github.com/rfielding/principia/edge"
	"testing"
)

func TestEdge(t *testing.T) {
	// This is a sidecar for a database on port 8023
	eDB := edge.Start("127.0.0.1", 8022, common.NewLogger("eDB/eWeb"))
	eDB.Listen(edge.Listener{
		Port: 8023,
		Name: "eDB/eWeb",
	})

	// This is a proxy on 8122 to a web server on 8123, talking to db on 8124
	eWeb := edge.Start("127.0.0.1", 8122, common.NewLogger("eWeb"))
	eWeb.Listen(edge.Listener{
		Port: 8123,
		Name: "eWeb",
	})
	eWeb.Knows(eDB.Endpoint)
	eWeb.Requires("eDB/eWeb", 8124)
}
