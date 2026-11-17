# csi-driver-athenz
csi-driver-athenz is a Container Storage Interface (CSI) driver plugin for Kubernetes, designed to work alongside cert-manager.


## Role certificates

Set `csi.cert-manager.athenz.io/role-certs` to a comma-separated list of
`<domain>:role.<role>` to also receive Athenz role certificates. See
[docs/role-cert.md](docs/role-cert.md) for the file layout, refresh behavior and
the `csi.cert-manager.athenz.io/refresh-interval` caution.
