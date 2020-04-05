package edge_test

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/rfielding/principia/common"
	"github.com/rfielding/principia/edge"
)

func TryTest(t *testing.T, err error) {
	if err != nil {
		t.Logf("Failed test: %v", err)
		t.FailNow()
	}
}

func testParseHttp(t *testing.T, conn net.Conn, logger common.Logger) {
	brdr := bufio.NewReader(conn)
	for {
		line, _, _ := brdr.ReadLine()
		logger.Info("%s", string(line))
		if string(line) == "" {
			break
		}
	}
	conn.Close()
}

func TestEdge(t *testing.T) {
	// can be per-identity, must be signed by trustPath
	certPath := "./test_cert.pem"
	keyPath := "./test_key.pem"
	// every peer trusts trustPath certs
	trustPath := "./test_cert.pem"

	testLogger := common.NewLogger("integrationTest")

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

	eAuth1, err := edge.Start(&edge.Edge{
		CertPath:  certPath,
		KeyPath:   keyPath,
		TrustPath: trustPath,
	})
	TryTest(t, err)
	defer eAuth1.Close()

	eAuth2, err := edge.Start(&edge.Edge{
		CertPath:  certPath,
		KeyPath:   keyPath,
		TrustPath: trustPath,
	})
	TryTest(t, err)
	defer eAuth2.Close()

	mongo, err := edge.Start(&edge.Edge{
		CertPath:  certPath,
		KeyPath:   keyPath,
		TrustPath: trustPath,
	})
	TryTest(t, err)
	defer mongo.Close()

	eWeb, err := edge.Start(&edge.Edge{
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
			Dir:       ".",
			HttpCheck: "/",
		},
	}))
	testLogger.Info("Available eDB:%d %s", eDB.Port, common.AsJsonPretty(eDB.Available()))

	TryTest(t, mongo.Spawn(edge.Listener{
		Name: "mongo_eweb",
		Run: edge.Command{
			EditFn: func(lsn *edge.Listener) {
				lsn.Run.Cmd[5] = fmt.Sprintf("127.0.0.1:%d:27017", lsn.Port)
			},
			Stdout: ioutil.Discard,
			Stderr: ioutil.Discard,
			Cmd: []string{
				"docker",
				"run",
				"--name", "mongo_eweb",
				"-p", "127.0.0.1:27017:27017",
				"mongo",
			},
			Dir:       ".",
			HttpCheck: "/",
		},
	}))
	testLogger.Info("Available mongo:%s %s", mongo.Port, common.AsJsonPretty(mongo.Available()))

	TryTest(t, eAuth1.Spawn(edge.Listener{
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
			Static:    ".",
			HttpCheck: "/",
		},
	}))

	//time.Sleep(10 * time.Second)

	// Allocate an arbitrary port for the db
	eDB_eWeb_port := edge.AllocPort()
	eAuth_port := edge.AllocPort()
	mongo_port := edge.AllocPort()
	eWeb.Peer(eDB.Host, eDB.Port)
	eWeb.Peer(eAuth1.Host, eAuth1.Port)
	eWeb.Peer(eAuth2.Host, eAuth2.Port)
	eWeb.Peer(mongo.Host, mongo.Port)
	eWeb.Tunnel("eDB_eWeb", eDB_eWeb_port)
	eWeb.Tunnel("eAuth", eAuth_port)
	eWeb.Tunnel("mongo_eweb", mongo_port)

	// Log info about it
	testLogger.Info("Available eAuth1:%d %s", eAuth1.Port, common.AsJsonPretty(eAuth1.Available()))
	testLogger.Info("Available eAuth2:%d %s", eAuth2.Port, common.AsJsonPretty(eAuth2.Available()))
	testLogger.Info("Available mongo:%d %s", mongo.Port, common.AsJsonPretty(mongo.Available()))
	testLogger.Info("Available eDB:%d %s", eDB.Port, common.AsJsonPretty(eDB.Available()))
	testLogger.Info("Available eWeb:%d %s", eWeb.Port, common.AsJsonPretty(eWeb.Available()))

	eDB_eWeb_data, err := eDB.GetFromPeer(eWeb.PeerName(), "/eDB_eWeb/")
	TryTest(t, err)
	testLogger.Info("Got: %s", eDB_eWeb_data)

	eWeb_data, err := eWeb.GetFromPeer(eWeb.PeerName(), "/eDB_eWeb/")
	TryTest(t, err)
	testLogger.Info("Got: %s", eWeb_data)

	eWeb_data2, err := eWeb.GetFromPeer(eWeb.PeerName(), "/eWeb/")
	TryTest(t, err)
	testLogger.Info("Got: %s", eWeb_data2)

	// Talk to actual service for comparison
	if true {
		eDB_svc_name := eDB.Available()["eDB_eWeb"].Endpoint
		url := fmt.Sprintf("http://%s/", eDB_svc_name)
		req, err := http.NewRequest("GET", url, nil)
		TryTest(t, err)
		cl := http.Client{}
		testLogger.Info("GET %s via local websocket", url)
		res, err := cl.Do(req)
		TryTest(t, err)
		data, err := ioutil.ReadAll(res.Body)
		TryTest(t, err)
		testLogger.Info("%s", string(data))
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.FailNow()
		}
	}

	// Talk to local Tunnel
	if true {
		eDB_svc_name := eWeb.Available()["eDB_eWeb"].Endpoint
		url := fmt.Sprintf("http://%s/", eDB_svc_name)
		req, err := http.NewRequest("GET", url, nil)
		TryTest(t, err)
		cl := http.Client{}
		testLogger.Info("GET %s via remote websocket", url)
		res, err := cl.Do(req)
		TryTest(t, err)
		data, err := ioutil.ReadAll(res.Body)
		TryTest(t, err)
		testLogger.Info("%s", string(data))
		res.Body.Close()
		if res.StatusCode != http.StatusOK {
			t.FailNow()
		}
	}

	testLogger.Info("https://%s/eWeb/", eWeb.PeerName())

	time.Sleep(5 * time.Minute)
}
