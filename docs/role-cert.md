# Role certificates

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

With `--enable-keystore`, each role also gets `<role>.pkcs12` and `<role>.jks`
(alias `1`, as SIA writes them), encrypted with the service keystore password.

## Refresh behavior

Role certificates are re-issued together with the service certificate. Every
issuance asks ZTS for all listed roles again, each with a new private key. The
next issuance happens at the earliest of:

| Trigger | When |
|---|---|
| `csi.cert-manager.athenz.io/refresh-interval` | The configured interval (default `24h`) |
| Role certificate lifetime | 2/3 of the shortest role certificate's lifetime |
| A role that ZTS refused | 10 minutes later |

So a role certificate can renew sooner than `refresh-interval`, never later.

The mount fails until every role certificate has been issued. On renewal, a role
that ZTS refuses keeps its previous certificate and is retried after 10 minutes,
so the service certificate still renews.

## refresh-interval

```yaml
volumeAttributes:
  csi.cert-manager.athenz.io/refresh-interval: "12h"
```

The value is a Go duration such as `90m` or `12h`. The minimum is `60m`. An
empty, unparsable or shorter value is ignored and the default of `24h` is used.

Keep the value as high as your workload tolerates. Every pod reissues on this
interval, and each reissue sends one certificate request to the service
certificate signer plus one `POST /rolecert` to ZTS per role. Across many pods
and roles a low interval multiplies into a steady request load and can overload
the signing service. Do not lower it to "refresh faster" for one workload; if
role certificates must rotate more often, ask the platform team first.

## File write order

In `in-place` write mode the files are updated one by one. Each certificate is
written after its own private key and keystores (role certificates before the
service certificate), so a consumer that watches only the certificate file never
reads a new certificate with an old key.
