# Single-node kubernetes cluster

Andrés Hernández - tonejito - 🐰
Licensed under the GPLv3 license

This set of files deploys a Vagrant VM using VirtualBox that has a single-node kubernetes cluster deployed via `kubeadm`.

The base OS is **Ubuntu 18.04 LTS** as required by the CKS certification.
The Linux user is `vagrant`, and it has `cluster-admin` privileges in the cluster.
The _master_ node is untainted to allow to operate in a single-node fashion.

## Virtual Machine

The VirtualBox VM has the following settings:

- Ubuntu 18.04 LTS (`ubuntu/bionic64`)
- 2 vCPUs
- 8 GB RAM

The VM is configured to have the following network interfaces:

| Interface | Mode      | Default? | Metric | Notes |
|:---------:|:---------:|:--------:|:------:|:-----:|
| `eth0`    | NAT       | yes\*    | 100    | Required by `vagrant`
| `eth1`    | Host-only |  NO      |  50    | For local communication with the host
| `eth2`    | Bridged   | YES      |  50    | Bridged with host network on the physical `eth0` interface

\* NOTE: The interface with the lower metric is the one with higher priority

## Software

The following items are installed in the "cluster":

| Software	| Version |
|:-------------:|:-------:|
| Ubuntu LTS	| 18.04
| Docker	| v20.10.12
| Containerd	| v1.4.12
| Kubernetes	| v1.22
| Helm		| v3.7.2
| Flannel	| v0.15.1
| Ingress NGINX	| v1.1.0
| k8s dashboard	| v2.4.0
| krew		| v0.4.2
| krew neat	| _latest_

The dashboard is available at the following URL:

- `https://dashboard.<DASHED-IP-ADDRESS>.nip.io/`

Where `<DASHED-IP-ADDRESS>` is the IP address of the `eth2` interface (bridged) separated by **dashes** (not dots).
You can get that value with:

```
$ ip addr show dev eth2 | grep '\<inet\>' | awk '{print $2}' | cut -d / -f 1
```

## Notes

- The cgroup driver has been set to `systemd` in **docker** and **kubernetes**
- The only application deployed is the `kubernetes-dashboard`
- The `ingress-nginx-controller` deployment has been patched to expose the NGINX ingress on the host network on ports 80 and 443
- The `vagrant` user has a `~/.kube/config` file to login as the `kubernetes-admin` user in the cluster
    - This user also has `krew` installed with the `neat` plugin
- A set of files are created in the `log/` directory that contain debug logs for the whole deploy and `kubeadm init` process to set up the cluster
- A set of files are created in the `resources/` directory, those files represent the resources deployed in the cluster, and can be kept for reference.
    - There is a `worker-join.sh` script to allow workers to join this cluster
