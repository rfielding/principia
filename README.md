Principia
=========

![diagram.gif](diagram.gif)

Principia is a project that aims to simplify the wiring of network programs
into applications.  It tries to follow the example of `ssh` as much as possible,
rather than `kubernetes` or `docker-compose`.  Specifically, it has these goals:

- Reduce config as much as possible.  If config is complex, it can create more problems than it is solving.
- Chose integration over flexibility.  Being opinionated will make it easier to do common tasks that are often possible in theory, but too hard to do in other frameworks.
- X509 certificates are an incredible source of pain for users.  So, we want to handle securing traffic in the mesh; without onerous impositions on the user.
- Single-binary and standalone.  This should be a utility that can be used to stand up a network of services, or to stand up an integration test.  A key thing is to make it easy to avoid port conflicts, so that services don't interfere with each other.
- Do not rely on DNS or rely too heavily on containers.  Talking direct to peer services is what creates a lot of config; because TLS gets pushed onto the app developers and users.  Load balancing considerations get pushed onto users.
- Instead, rely heavily on tunneling; like common `ssh` setups.  In `ssh`, it is easy to spawn a command on a remote machine, and give that command some tunnels to reach some other services.  But `ssh` doesn't do load balancing or discovery.
- Hide load-balancing and discovery and encryption in the tunnels.  Processes only see 127.0.0.1.  They talk only to local ports.

![edge.png](edge.png)

This example resembles a simple integration test we have in package `edge`, run like this:
```bash
./build
```

As an example, every Edge (in purple) has a TLS entry point for entering through the "front door", and a plaintext private entry point for entering through the "back door".  In the back, services think that everything is bound to 127.0.0.1.  The process is an Edge proxy on the front, and a sidecar on the back; to allow the user to maintain the illusion of isolation.

In the example, we have a web app that has two dependencies.  It can talk to them through reverse proxy when they happen to be http services (purple).  Or if they are non-http databases (ie: Postgres, MySQL, Mongo), then a tunnel port can easily be setup (yellow).  The tunnel reaches other machines _only_ over TLS.  But because there is only one TLS entry point, websockets are used to transport non-http traffic.

> This is probably one of the most important features.  With tunnels, reverse proxies are somewhat redundant in the backend.  Reverse proxies are convenient for creating a single-origin illusion for the Javascript front-end.

Like `ssh`, the daemons are all rather similar.  An Edge just needs enough information to run a TLS server for the Edge.

```go
// This is a sidecar for a database on random port
eDB, err := edge.Start(&edge.Edge{
  CertPath:  certPath,
  KeyPath:   keyPath,
  TrustPath: trustPath,
})
```

Once this edge exists, we can spawn commands in it, very much like `ssh`.  In this example, we are:

- Spawning a process and naming it so that a reverse proxy of `/eDB_eWeb/` can reach it.
- When it runs, it will pick a port for the spawn if we do not specify it.
- The port will be bound to a listener socket.
- We can inject the chosen port into the command-launch with a few methods (environment vars, parameter overwrite, etc)

```go
eDB.Spawn(edge.Listener{
  Name: "eDB_eWeb", // an eDB instance, with a schema for eWeb
  Run: edge.Command{
    EditFn: func(lsn *edge.Listener) {
      // This is how we let our randomly assigned port override the one in the command
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
})
```

> Note HttpCheck.  When the port it spawns on becomes reachable with a GET on this URL, then the spawn returns.  This eliminates the sleep tricks and complex config to do readiness probes that are common in other frameworks.

When this command is running, the Edge and Sidecar will have the same http handling, only differing in the Edge TLS requirement.  This lets processes talk back to their sidecar without any certificate setup.  The sidecars will speak TLS among themselves.

- If multiple Edges Spawn things with the same name, then load-balancing will be done automatically.
- When a spawn dies, it will eventually fall out of the list of Volunteers to handle the load balance.

Another example of a spawn is a static web server.

```go
// Launch a static web server.  We don't need a container for this.
eWeb.Spawn(edge.Listener{
  Name:   "eWeb",
  Expose: true,
  Run: edge.Command{
    Static:    ".",
    HttpCheck: "/",
  },
})
```

This web server will have a dependency on a database.  If the database isn't http, it will need to have a tunnel.

```go
// We point to peers, so that we can make TLS connections to find out what is available
eWeb.Peer(eDB.Host, eDB.Port)
eWeb.Tunnel("eDB_eWeb", eDB_eWeb_port)
```

The tunnel can be found on the other machine, because when we hit the endpoint `GET /available`, we get a data structure that tells us what reverse proxy prefixes (and websockets) are available in the proxy.

```json
{
  "eAuth": {
    "Endpoint": "127.0.0.1:8038",
    "Volunteers": [
      "127.0.0.1:8024",
      "127.0.0.1:8026"
    ]
  },
  "eDB_eWeb": {
    "Endpoint": "127.0.0.1:8037",
    "Volunteers": [
      "127.0.0.1:8022"
    ]
  },
  "eWeb": {
    "Endpoint": "127.0.0.1:8036",
    "Expose": true
  },
  "mongo_eweb": {
    "Endpoint": "127.0.0.1:8039",
    "Volunteers": [
      "127.0.0.1:8028"
    ]
  },
  "sidecarInternal": {
    "Endpoint": "127.0.0.1:8031"
  }
}
```

Clients only care that a named service they needs exists.  If we depend on `eAuth`, then we can see that it's in here.  An Endpoint with no volunteers will be handled locally.  We can talk to the sidecar, which looks exactly like the Edge, except it is plaintext.  If there are Volunteers, then one will be chosen randomly to service the request; across a TLS socket.  For example:

We can reach this page at `/eWeb/`.

```html
<html>
  <head>Testing</head>
  <body>
    It works!
    <a href=/eDB_eWeb/>Try this!</a>
  </body>
</html>
```

We can go to any edge, and we will get a page back, given that the edge knows about these two services.
