package edge_test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"github.com/rfielding/principia/auth"
	"github.com/rfielding/principia/common"
	"github.com/rfielding/principia/edge"
	"io/ioutil"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestWSKey(t *testing.T) {
	stdKey := "dGhlIHNhbXBsZSBub25jZQ=="
	stdAccept := edge.WsSecWebSocketAccept(stdKey)
	if stdAccept != "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=" {
		t.FailNow()
	}
	stdKey = edge.WsSecWebSocketKey()
	fmt.Printf("%s\n", stdKey)
}

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

type UserDB map[string]map[string][]string

func TestEdge(t *testing.T) {
	// Load a userr database
	dbBytes, err := ioutil.ReadFile("./users.json")
	if err != nil {
		t.Logf("unable to open user database: %v", err)
		t.FailNow()
	}
	var db UserDB
	err = json.Unmarshal(dbBytes, &db)
	if err != nil {
		t.Logf("unable to parse user database: %v", err)
		t.FailNow()
	}

	// A simple algorithm for linking in new attributes to claims
	linkClaims := func(oidc_claims interface{}) map[string][]string {
		// estract given email if possible
		given_email := ""
		oidcMap, ok := oidc_claims.(map[string]interface{})
		if ok {
			oidcMapEmail, ok := oidcMap["email"].(string)
			if ok {
				given_email = oidcMapEmail
			}
		}

		// Find or make an entry
		entry := db[given_email]
		if entry == nil {
			entry = map[string][]string{}
		}

		// Modify it as necessary
		if given_email != "" {
			entry["email"] = common.AppendToStringSet(entry["email"], given_email)
		}

		return entry
	}

	// OAuth config
	oauthconfig := &auth.OAuthConfig{
		OAUTH2_CLIENT_ID:         "117885021249-ptm2h0v2oqfljq5hbj785trpcrb1m3s4.apps.googleusercontent.com",
		OAUTH2_CLIENT_SECRET:     "URC1G9gQ_LBWGoyg7JWAWimh",
		OAUTH2_REDIRECT_CALLBACK: "/oidc/cb",
		OAUTH2_REDIRECT_URL:      "https://localhost:8032",
		OAUTH2_PROVIDER:          "https://accounts.google.com",
		OAUTH2_SCOPES:            "openid email profile email https://www.googleapis.com/auth/youtube.readonly https://www.googleapis.com/auth/profile.agerange.read",
		// Provide a way to link claims to extra attributes
		LinkClaims: linkClaims,
	}

	idFiles := edge.IdentityFiles{
		KeyPath:   "./test_key.pem",
		CertPath:  "./test_cert.pem",
		TrustPath: "./test_cert.pem",
	}

	testLogger := common.NewLogger("integrationTest")

	/**
	Spawn a bunch of Edge machines.  They are
	effectively identical.
	*/

	// This is a sidecar for a database on random port
	eDB, err := edge.Start(&edge.Edge{
		IdentityFiles: idFiles,
		OAuthConfig:   oauthconfig,
	})
	TryTest(t, err)
	defer eDB.Close()

	eAuth1, err := edge.Start(&edge.Edge{
		IdentityFiles: idFiles,
		OAuthConfig:   oauthconfig,
	})
	TryTest(t, err)
	defer eAuth1.Close()

	eAuth2, err := edge.Start(&edge.Edge{
		IdentityFiles: idFiles,
		OAuthConfig:   oauthconfig,
	})
	TryTest(t, err)
	defer eAuth2.Close()

	mongo, err := edge.Start(&edge.Edge{
		IdentityFiles: idFiles,
		OAuthConfig:   oauthconfig,
	})
	TryTest(t, err)
	defer mongo.Close()

	redis_eWeb, err := edge.Start(&edge.Edge{
		IdentityFiles: idFiles,
		OAuthConfig:   oauthconfig,
	})
	TryTest(t, err)
	defer redis_eWeb.Close()

	eWeb, err := edge.Start(&edge.Edge{
		Host:          "localhost",
		IdentityFiles: idFiles,
		OAuthConfig:   oauthconfig,
	})
	TryTest(t, err)
	defer eWeb.Close()

	/*
		  In the edge machines, we should spawn some commands.
			TODO: wait until port can be reached
	*/

	theDBs := []*edge.Edge{eDB, mongo}

	for i, d := range theDBs {
		TryTest(t, d.Exec(edge.Spawn{
			Name: "eDB_eWeb",
			Run: edge.Command{
				Override: func(spawn *edge.Spawn) {
					spawn.Run.Cmd[4] = fmt.Sprintf("127.0.0.1:%d:5984", spawn.Port)
					spawn.Run.Cmd[6] = fmt.Sprintf("%s_%d", spawn.Name, i)
				},
				Stdout: ioutil.Discard,
				Stderr: ioutil.Discard,
				Cmd: []string{
					"docker",
					"run",
					"--rm",
					"-p", "127.0.0.1:5984:5984",
					"--name", "eDB_eWeb",
					"-e", "COUCHDB_USER=admin",
					"-e", "COUCHDB_PASSWORD=password",
					"couchdb",
				},
				Dir:       ".",
				HttpCheck: "/",
			},
		}))
		TryTest(t, d.Exec(edge.Spawn{
			Name: "mongo_eWeb",
			Run: edge.Command{
				Override: func(spawn *edge.Spawn) {
					spawn.Run.Cmd[4] = fmt.Sprintf("127.0.0.1:%d:27017", spawn.Port)
					spawn.Run.Cmd[6] = fmt.Sprintf("%s_%d", spawn.Name, i)
				},
				Stdout: ioutil.Discard,
				Stderr: ioutil.Discard,
				Cmd: []string{
					"docker",
					"run",
					"--rm",
					"-p", "127.0.0.1:27017:27017",
					"--name", "mongo_eWeb",
					"mongo",
				},
				Dir: ".",
			},
		}))
		testLogger.Info("Available mongo:%s %s", d.Port, common.AsJsonPretty(d.CheckAvailability().Available))
	}

	eAuth1Svr, err := auth.NewServer(oauthconfig, eAuth1.Trust, eAuth1.Logger)
	TryTest(t, err)
	TryTest(t, eAuth1.Exec(edge.Spawn{
		Name:        "oidc",
		PortIntoEnv: "EAUTH_PORT",
		KeepPrefix:  true,
		Run: edge.Command{
			Server: eAuth1Svr,
		},
	}))

	eAuth2Svr, err := auth.NewServer(oauthconfig, eAuth2.Trust, eAuth2.Logger)
	TryTest(t, eAuth2.Exec(edge.Spawn{
		Name:        "oidc",
		PortIntoEnv: "EAUTH_PORT",
		KeepPrefix:  true,
		Run: edge.Command{
			Server: eAuth2Svr,
		},
	}))

	// If this app is just passed in a list of peers...
	eWebPeers := []*edge.Edge{eDB, eAuth1, eAuth2, mongo, redis_eWeb}

	// And declares its tunnels....
	for _, p := range eWebPeers {
		eWeb.Peer(p.Host, p.Port)
	}
	eWeb.Tunnel("eDB_eWeb", edge.AllocPort())
	eWeb.Tunnel("mongo_eWeb", edge.AllocPort())
	eWeb.Tunnel("redis_eWeb", edge.AllocPort())

	// The app can spawn
	TryTest(t, eWeb.Exec(edge.Spawn{
		Name: "eWeb",
		Run: edge.Command{
			Server: &http.Server{
				Handler: http.FileServer(http.Dir(".")),
			},
			HttpCheck: "/",
		},
	}))

	TryTest(t, redis_eWeb.Exec(edge.Spawn{
		Name: "redis_eWeb",
		Run: edge.Command{
			Override: func(spawn *edge.Spawn) {
				spawn.Run.Cmd[4] = fmt.Sprintf("127.0.0.1:%d:6379", spawn.Port)
				spawn.Run.Cmd[6] = fmt.Sprintf("%s_%d", spawn.Name, 0)
				spawn.Run.Cmd[8] = fmt.Sprintf("SIDECAR_INTERNAL=%s", spawn.Owner.SidecarName())
			},
			Stdout: ioutil.Discard,
			Stderr: ioutil.Discard,
			Cmd: []string{
				"docker",
				"run",
				"--rm",
				"-p", "127.0.0.1:6379:6379",
				"--name", "redis_eWeb",
				"-e", "SIDECAR_INTERNAL=127.0.0.1:?",
				"redis",
			},
			Dir: ".",
		},
	}))
	testLogger.Info("Available redis:%s %s", redis_eWeb.Port, common.AsJsonPretty(redis_eWeb.CheckAvailability().Available))

	// Log info about it
	testLogger.Info("Available eAuth1:%d %s", eAuth1.Port, common.AsJsonPretty(eAuth1.CheckAvailability().Available))
	testLogger.Info("Available eAuth2:%d %s", eAuth2.Port, common.AsJsonPretty(eAuth2.CheckAvailability().Available))
	testLogger.Info("Available mongo:%d %s", mongo.Port, common.AsJsonPretty(mongo.CheckAvailability().Available))
	testLogger.Info("Available eDB:%d %s", eDB.Port, common.AsJsonPretty(eDB.CheckAvailability().Available))
	testLogger.Info("Available redis_eWeb:%d %s", redis_eWeb.Port, common.AsJsonPretty(redis_eWeb.CheckAvailability().Available))
	testLogger.Info("Available eWeb:%d %s", eWeb.Port, common.AsJsonPretty(eWeb.CheckAvailability().Available))

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
		eDB_svc_name := eDB.CheckAvailability().Available["eDB_eWeb"].Endpoint
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
		eDB_svc_name := eWeb.CheckAvailability().Available["eDB_eWeb"].Endpoint
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

	testLogger.Info("https://%s/oidc/login?state=/eWeb/", eWeb.PeerName())

	time.Sleep(5 * time.Minute)
}
