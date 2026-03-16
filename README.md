<p align="center">
	<h1 align="center">Regi <img width="32" height="32" alt="image" src="https://github.com/user-attachments/assets/e7390c74-c5c1-4ac8-9686-7c99a34a3c66" /></h1>
</p>
<p align="center">
    Use an image store like Docker as a real OCI image registry to simplify pulls of
    locally built images.
</p>

## Installation

```bash
go install github.com/ndbaker1/regi@latest
```

## Usage

For example; if you are running a Docker-in-Docker setup such as KinD, you can
insert this block into [containerd hosts config](https://github.com/containerd/containerd/blob/main/docs/hosts.md#setup-default-mirror-for-all-registries)
to add a fallback to docker host.
```toml
# /etc/containerd/certs.d/_default/hosts.toml
[host."http://host.docker.internal:5000"]
    capabilities = ["pull", "resolve"]
```

start regi:
```bash
> regi
time=2026-02-24T11:11:15.790-08:00 level=INFO msg="starting registry" addr=:5000
```
