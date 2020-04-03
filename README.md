Principia
=========

This project aims to make it easy to wire together independent web servers.  The various sidecar projects that have picked up momentum suffer from complexity.  The _SSH_ protocol seems a better model on which to build such a system.

- Allow web servers to run entirely isolated, where every dependency can be a pre-determined localhost-bound port.
- Services can default to serving up plaintext localhost-bound ports.  Services should be completely spared the complexity of dealing with X509 certificates.
- Your permission to speak to something should be the existence of a port over which to do this.

The general strategy is to mimic ssh, except:

- The primary goal is to minimize configuration.
- Try to hide where everything is.
- Hide the fact that things are load balanced.
- Hide TLS completely from users.
- Instead of port 22 speaking an app specific ssh protocol, make 22 be a way to transport web sockets
- Instead of having to explicitly specify the ip address of destinations, have spawned ports announce what they OFFER, and web services are configured to point to what they REQUIRE.
- Every node knows its own IP address and how it reaches nodes that it REQUIRES.
- Similar offerings can be load-balanced as equivalent services.
- Discovering what is offered is done by leasing out a directory entry.  When a node fails to renew its lease, it falls out of the offerings.

Every node can also be used as a reverse proxy to reach services that exist in the mesh.

- In addition to ssh-like functionality where there are localhost-bound ports that websocket-transport from REQUIRED to OFFERED services; it can act as a reverse proxy.
- The reverse proxy gives a load-balanced front-end that appears as a single-site to the mesh.  This allows for Javascript static apps that consume services.
- The reverse proxy itself has an API for registering offerings, and making config changes.

# Service Example

We always launch some sidecars, that are analagous to sshd daemons.

## The Authorization service Example

Here we launch an example authorization service.  Note that when the Listener
is spawned, the port that was chose is written into an env var `EAUTH_PORT`
on startup.  This is how we can have a mesh where users don't deal with
ports; and ports can be deconflicted so that we can run many instances on one
machine.

```go
  // Create an Edge that will spawn on a random port
	eAuth, err := edge.Start(&edge.Edge{
		Name:      "eAuth",
		CertPath:  certPath,
		KeyPath:   keyPath,
		TrustPath: trustPath,
	})
	TryTest(t, err)
	defer eAuth.Close()

  // Tell it to run a program with random port, with env var EAUTH_PORT injected
	TryTest(t, eAuth.Spawn(edge.Listener{
		PortIntoEnv: "EAUTH_PORT",
		Run: edge.Command{
			Cmd: []string{"/usr/bin/authsvr"},
		},
	}))
```

As a result of this, we can see that the sidecar spawned an https
service on 0.0.0.0:8022.  Since sidecars are talking to each other,
they can deal with the TLS setup, and we don't need to think about it.

The actual authorization service runs on 127.0.0.1:8024, so that
nothing can talk to it except the Edge process bound
to 0.0.0.0:8022 and 127.0.0.1:8023.

```json
//Available eAuth:8022
{
  "eAuth": {
    "Endpoint": "127.0.0.1:8024"
  },
  "sidecarInternal": {
    "Endpoint": "127.0.0.1:8023"
  }
}
```

- `eAuth` is where we can talk to the command, over whatever TCP protocol
  it speaks.
- `sidecarInternal` is a standardized name for an http handler that has the
  same endpoints as the TLS enabled external port `0.0.0.0:8022`.  This way,
  the internal service just speaks plaintext http to the sidecar, even
  though external clients coming in via 8022 need to use TLS.  The internal
  port may also expose some more sensitive endpoints than are reachable remotely.

## Database Example

This database may speak any protocol, such as Mongo, Postgres, etc.  All that
matters is that it is launched on a port that our Edge chose and injected
into the service.  It is nearly identical conceptually.  The code to launch
is the same information as for the auth server, which is the same information
that needs to be given to an ssh command to spawn into a remote sshd.

```json
// Available eDB:8028
{
  "eDB_eWeb": {
    "Endpoint": "127.0.0.1:8030"
  },
  "sidecarInternal": {
    "Endpoint": "127.0.0.1:8029"
  }
}
```

## Web Server

And here we have something less trivial.  
We have an app that has actual dependencies.

First we start the edge process.  It's pretty much the same as the others.

```go
// This is a proxy on 8122 to a web server on 8123, talking to db on
eWeb, err := edge.Start(&edge.Edge{
  Name:      "eWeb",
  CertPath:  certPath,
  KeyPath:   keyPath,
  TrustPath: trustPath,
})
TryTest(t, err)
defer eWeb.Close()

```

But here, we plan on having ports match up when we spawn our listener.
So we have a listener that allows us to specifically inject config
dependency.  In this case, we need to Spawn a listener and its
port is plugged into `EWEB_PORT` before the command is actually run.

We also need to come up with a local `EDB_PORT` and `EAUTH_PORT` for
services that we depend on.  These are 127.0.0.1 bound ports, and
are not the same ports as used by actual services.

```go
// Allocate an arbitrary port for the db
eDB_eWeb_port := edge.AllocPort()
eAuth_port := edge.AllocPort()

// Spawn the web server talking to the db
TryTest(t, eWeb.Spawn(edge.Listener{
  Expose:      true,
  PortIntoEnv: "EWEB_PORT",
  Run: edge.Command{
    Cmd: []string{"/usr/bin/eWeb"},
    Env: []string{
      "EDB_PORT", eDB_eWeb_port.String(),
      "EAUTH_PORT", eAuth_port.String(),
    },
  },
}))
```

This is the magic that allows this to work.  We tell all Edges about
each other in dependency order that they need.  In the future, gossip
about who is where may allow everyone to know about everyone else.

What is important is that if we require a service, we need a local
port to talk to it (in plaintext).  Services match and load balance
by name.  So if we talk to local `eAuth` service port, we speak plaintext
to it.  The Edges will transport among themselves a TLS tunnel.

Because we don't use DNS to try to wire apps together, we just speak to one
port only.  There is no TLS config, and we speak plaintext.  Note
that we have an `eAuth` and an `eAuth2` object.  The TCP port
`eAuth_port` will randomly load balance between them.  But our client
code can't tell.  It just talks to a single hardcoded port as plaintext.

```go
eWeb.Peer(eDB.Host, eDB.Port)
eWeb.Peer(eAuth.Host, eAuth.Port)
eWeb.Peer(eAuth2.Host, eAuth.Port)
eWeb.Requires("eDB_eWeb", eDB_eWeb_port)
eWeb.Requires("eAuth", eAuth_port)
```

In the output, we can see the effects.  `eWeb` needs to ask
peers what is available.  

```json
// eDB_eWeb:127.0.0.1:8028: GET /available
// eAuth:127.0.0.1:8022: GET /available
// eAuth:127.0.0.1:8022: GET /available
// Available eWeb:8031
```

A service that is `Expose` can be reached via https reverse proxy from the
outside.  A service that has volunteers means that it's not actually
running on this edge, but will do a reverse proxy URL to a randomly
chosen volunteer.  The service need not even be http, because it will
use a WebSocket.


```json
{
  "eAuth": {
    "Endpoint": "127.0.0.1:8034",
    "Volunteers": [
      "127.0.0.1:8022",
      "127.0.0.1:8022"
    ]
  },
  "eDB_eWeb": {
    "Endpoint": "127.0.0.1:8033",
    "Volunteers": [
      "127.0.0.1:8028"
    ]
  },
  "eWeb": {
    "Endpoint": "127.0.0.1:8035",
    "Expose": true
  },
  "sidecarInternal": {
    "Endpoint": "127.0.0.1:8032"
  }
}
```

We can see that reverse proxy url prefixes are setup for us.
If we ask for `/eWeb/hello`, we are asking `eWeb` to service `GET /hello`
for us.  Whether it's implemented on this Edge, or on a remote Volunteer
does not matter.  It will look the same to the caller.

```json
// eWeb:127.0.0.1:8031: GET /eWeb/hello
// eWeb:127.0.0.1:8031: GET /eWeb/hello -> eWeb 8035 /hello
//  
// eWeb:127.0.0.1:8031: GET /eDB_eWeb/hello
// eDB_eWeb:127.0.0.1:8028: GET /available
// eAuth:127.0.0.1:8022: GET /available
// eAuth:127.0.0.1:8022: GET /available
// eWeb:127.0.0.1:8031: GET /eDB_eWeb/hello -> 127.0.0.1:8028 /eDB_eWeb/hello
```

Local Ports
===========

The point of talking to local ports is to:

- keep services from having to track changes to participating dependents (remote endpoints)
- keep services from needing a TLS config to speak to the other end, as all TLS is done transparently between edges; similar to sshd port 0.0.0.0:22.
- hide load balancing.  these ports are always up, and will send to an arbitrary service that meets the requirements.
- Since everything tunnels over WebSockets, http authentication and authorization mechanisms can be used (JWT), even over protocols (such as mongo) that have no idea that http exists.
- Use Spiffe certificates internally, but users never see it at all.

Give that the app knows about the API, it can inspect what is available; to programmatically handle finding its dependencies.  If it cannot do this, then the dependencies would need to be hard-coded endpoints.

The api would be what we talk locally with, while the edge is the only entry point from a remote machine.  They might have the same handlers.

The Edge (analagous to Data Plane)
=========

- The only ports that are network-exposed are edge.  These are analagous to the port 22 in sshd.
- The edge serves up static content
- The edge serves up APIs for Javascript consumption
- Uses an ACME certificate.

The API (analagous to Control Plane)
========

- A superset of handlers that show up in the edge
- Includes private APIs that cannot be exposed at the edge
- Allow for the registration of OFFERED endpoints, similar to Envoy cluster.
- Can register REQUIRED ports, similar to Envoy listener.
- REQUIRED ports will load balance to all OFFERED ports, which may be remote or local; and randomly chosen from what is available.

Containers
==========

The plan for containers is to just allow for full use of raw docker commands.
Features needed to create correct command-lines will need to be implemented.
A mix of local binary commands, docker commands, and some Edge internal handlers (like static Web Servers) should be very easy to mix together.
The point of this is to have a simple framework for integration testing a log of stuff together.
It should be easy to split across machines.  Currently in docker, this is often challenging to do without complicated wrappers around docker;
and usually it is not easy to fold in non-containerized commands
