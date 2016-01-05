midonet-kubernetes
==================

**This is still pre-alpha and aggressively under development. Please don't use this.**

The MidoNet network plugin for Kubernetes integration.

Prerequisites
=============

**`midonet-kubernetes` runs only on Ubuntu 14.04 LTS at this moment.**

- OpenStack deployment at least the following components:
  + Keystone
  + Neutron
- MidoNet deployment
  + NSDB
  + Midolman on the same host as [Kubelet][kubelet]
- Kubenetes cluster
  + Kubelet launched with the `--network-plugin="midonet-kubernetes"` option on
    each minion

[kubelet]: http://kubernetes.io/v1.1/docs/admin/kubelet.html

Testing Deployment
==================

`script/deply.sh` deploys the current `midonet-kubernetes` to the single or
multiple hosts listed in the `.minion` file. Please make it sure you can access
the hosts with `ssh` and `scp`.

```
$ cat .minion
127.0.0.1
$ ./script/deploy.sh
```

Please make it sure you restart Kubelet processes after deploying the plugin.
