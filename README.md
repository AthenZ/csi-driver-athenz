# csi-driver-athenz
csi-driver-athenz is a Container Storage Interface (CSI) driver plugin for Kubernetes, designed to work alongside cert-manager.


## Role certificates

Set `csi.cert-manager.athenz.io/role-certs` to a comma-separated list of
`<domain>:role.<role>` to also receive Athenz role certificates. The driver
fetches each one from ZTS (`--zts`) using the pod's service certificate, with a
separate private key per role, and writes them next to the service certificate:

```yaml
volumeAttributes:
  csi.cert-manager.athenz.io/role-certs: "k8s.omega:role.reader,sports:role.writer"
```

```
k8s.omega:role.reader.cert.pem
k8s.omega:role.reader.key.pem
sports:role.writer.cert.pem
sports:role.writer.key.pem
```

The mount fails until every role certificate has been issued. On renewal, a role
that ZTS refuses keeps its previous certificate and is retried after 10 minutes,
so the service certificate still renews. Role certificates renew at 2/3 of their
lifetime, which can be sooner than `refresh-interval`.

With `--enable-keystore`, each role also gets `<role>.pkcs12` and `<role>.jks`
(alias `1`, as SIA writes them), encrypted with the service keystore password.
