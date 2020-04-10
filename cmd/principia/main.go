package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/rfielding/principia/common"
	"github.com/rfielding/principia/edge"
)

var jwt_pub = "JWT_PUB=LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHYk1CQUdCeXFHU000OUFnRUdCU3VCQkFBakE0R0dBQVFCSUVrNGpHL1FEMkZwNURxcmMrTzFPVy9CaG1BLwpKcmgyRFRaRWpybEZONnJYbTA0Vms0bUluNENZSmJ0VDdIQjc2cVJIeE9DNTFORVk0eFZHb1RUUVZta0Fnc3ljCllVdEdqZ3pKQUdTZExsSXZKSmtabWkrSjZBbWVtNng5UFZkajcxc2hHSnhNdjM4SDFTa2RRS29EZmllS3dZbFIKNENPUWFxdXdJVEpPYWd2R1VUQT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=="
var private_key = "PRIVATE_KEY=LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1JSGNBZ0VCQkVJQUludTVqbEdaU2Z6M2dMOWczOVNoeE5UaWtUQ0lvUWtFVVUyckdnV1ZJTm9TN3RlM2d1Uk8KK2VKb3FDZTd0Z3pKL1RZcGVxU055elE2UGVTS2JmZC91K2FnQndZRks0RUVBQ09oZ1lrRGdZWUFCQUVnU1RpTQpiOUFQWVdua09xdHo0N1U1YjhHR1lEOG11SFlOTmtTT3VVVTNxdGViVGhXVGlZaWZnSmdsdTFQc2NIdnFwRWZFCjRMblUwUmpqRlVhaE5OQldhUUNDekp4aFMwYU9ETWtBWkowdVVpOGttUm1hTDRub0NaNmJySDA5VjJQdld5RVkKbkV5L2Z3ZlZLUjFBcWdOK0o0ckJpVkhnSTVCcXE3QWhNazVxQzhaUk1BPT0KLS0tLS1FTkQgRUMgUFJJVkFURSBLRVktLS0tLQo="
var default_user_dn = "CN=localhost,OU=Engineering,O=Decipher Technology Studios,L=Alexandria,ST=Virginia,C=US"

func createNetwork(e *edge.Edge) error {
	return e.Exec(
		edge.Spawn{
			Name: "principia_network",
			Run: edge.Command{
				Cmd: []string{
					"docker",
					"create",
					"network",
					"principia",
				},
				SkipCheck: true,
			},
		},
	)
}

func pwd() string {
	d, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	return d
}
func launchJWT(e *edge.Edge) error {
	return e.Exec(
		edge.Spawn{
			Name: "jwt",
			Run: edge.Command{
				Override: func(spawn *edge.Spawn) {
					spawn.Run.Cmd[4] = fmt.Sprintf("127.0.0.1:%d:8080", spawn.Port)
					spawn.Run.Cmd[6] = fmt.Sprintf("%s_%d", spawn.Name, 0)
				},
				//Stdout: ioutil.Discard,
				//Stderr: ioutil.Discard,
				Cmd: []string{
					"docker",
					"run",
					"--rm",
					"-p", "127.0.0.1:8080:8080",
					"--name", "jwt",
					"--network", "principia",
					"-e", private_key,
					"-e", "TOKEN_EXP_TIME=30000",
					"-e", "REDIS_HOST=",
					"-e", "ENABLE_TLS=false",
					"-e", "ZEROLOG_LEVEL=debug",
					"-e", "JWT_API_KEY=Zm9vCg==",
					"-v", fmt.Sprintf("%s/users.json:/gm-jwt-security/etc/users.json", pwd()),
					"deciphernow/gm-jwt-security:latest",
				},
				//SkipCheck: true,
			},
		},
	)
}
func launchMongo(e *edge.Edge) error {
	return e.Exec(
		edge.Spawn{
			Name: "mongo_data",
			Run: edge.Command{
				Override: func(spawn *edge.Spawn) {
					spawn.Run.Cmd[4] = fmt.Sprintf("127.0.0.1:%d:27017", spawn.Port)
					spawn.Run.Cmd[6] = fmt.Sprintf("%s_%d", spawn.Name, 0)
				},
				//Stdout: ioutil.Discard,
				//Stderr: ioutil.Discard,
				Cmd: []string{
					"docker",
					"run",
					"--rm",
					"-p", "127.0.0.1:27017:27017",
					"--name", "mongo_data",
					"--network", "principia",
					"mongo",
				},
				//SkipCheck: true,
			},
		},
	)
}

func launchData(e *edge.Edge) error {
	return e.Exec(
		edge.Spawn{
			Name: "gm_data",
			Run: edge.Command{
				Override: func(spawn *edge.Spawn) {
					spawn.Run.Cmd[4] = fmt.Sprintf("127.0.0.1:%d:8181", spawn.Port)
					spawn.Run.Cmd[6] = fmt.Sprintf("%s_%d", spawn.Name, 0)
				},
				//Stdout: ioutil.Discard,
				//Stderr: ioutil.Discard,
				Cmd: []string{
					"docker",
					"run",
					"--rm",
					"-p", "127.0.0.1:8181:8181",
					"--name", "gm_data",
					"--network", "principia",
					"-e", "CLIENT_JWT_ENDPOINT_ADDRESS=host.docker.internal", // host.docker.internal may not work in your version of docker!
					"-e", "CLIENT_JWT_ENDPOINT_PORT=8023",
					"-e", "CLIENT_JWT_ENDPOINT_PREFIX=/jwt",
					"-e", "GMDATA_NAMESPACE=world",
					"-e", "GMDATA_NAMESPACE_USERFIELD=email",
					"-e", "JWT_API_KEY=Zm9vCg==",
					"-e", jwt_pub,
					"-e", "MASTERKEY=fark",
					"-e", "FILE_BUCKET=decipherers",
					"-e", "FILE_PARTITION=gmdatax",
					"-e", "USES3=false",
					"-e", "MONGOHOST=mongo_data_0",
					"-e", "MONGODB=mongo_data",
					"deciphernow/gm-data:latest",
				},
				//SkipCheck: true,
			},
		},
	)
}

func main() {
	logger := common.NewLogger("main")
	logger.Info("starting")

	certPath := "../../edge/test_cert.pem"
	keyPath := "../../edge/test_key.pem"
	trustPath := "../../edge/test_cert.pem"

	e0, err := edge.Start(&edge.Edge{
		CertPath:  certPath,
		KeyPath:   keyPath,
		TrustPath: trustPath,
		HttpFilter: func(r *http.Request) {
			r.Header.Set("USER_DN", default_user_dn)
		},
	})
	if err != nil {
		logger.Error("Unable to start edge: %v", err)
		return
	}
	defer e0.Close()

	createNetwork(e0)

	err = launchJWT(e0)
	if err != nil {
		logger.Error("Unable to start jwt: %v", err)
		return
	}

	err = launchMongo(e0)
	if err != nil {
		logger.Error("Unable to start mongo: %v", err)
		return
	}

	err = launchData(e0)
	if err != nil {
		logger.Error("Unable to start data: %v", err)
		return
	}

	logger.Info("Waiting for use")
	time.Sleep(10 * time.Minute)
}
