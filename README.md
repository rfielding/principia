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

Service Example
===============

Assume that there is always a local sidecar on 127.0.0.1:8022, and is the only thing that needs to be configured.

```
to: http://127.0.0.1:8022
GET /api/principia/available
      # endpoint      protocol      app
      0.0.0.0:443     edge
      127.0.0.1:8022  api+edge
      127.0.0.1:8090  authorization myapp
      127.0.0.1:27017 mongo         myapp
```

The point of talking to local ports is to:

- keep services from having to track changes to participating dependents (remote endpoints)
- keep services from needing a TLS config to speak to the other end, as all TLS is done transparently betwwen edges; similar to sshd port 0.0.0.0:22.
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
 

  
