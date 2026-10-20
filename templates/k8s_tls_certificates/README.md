# Kubernetes TLS certificates by HTTP

## Description

Zabbix template that alerts before TLS certificates in the cluster expire. It reads the Prometheus metrics of Traefik and cert-manager through the in-cluster Zabbix proxy, so it never touches private keys or certificate files (`acme.json`).

Background: HAProxy on tphaproxy1/2 verifies Traefik's certificate (`ssl verify required … sni req.hdr(host)`). If Traefik stops renewing its ACME certificates, HAProxy answers 503 for that name, so renewal failures must be noticed before expiry.

## What is checked

| Trigger | Severity | Fires when |
|---|---|---|
| Traefik certificate `{#CN}` expires in … | High | Less than `{$CERT.EXPIRY.HIGH}` days (7) left. |
| Traefik certificate `{#CN}` expires in … | Warning | Less than `{$CERT.EXPIRY.WARN}` days (20) left. Traefik renews at 30 days, so renewal has failed for about 10 days. Depends on the High trigger. |
| cert-manager certificate `{#NAMESPACE}/{#NAME}` expires in … | High / Warning | Same thresholds for cert-manager `Certificate` resources. |
| cert-manager certificate … is not Ready | Warning | The Ready condition has not been True for `{$CERT.NOT_READY.TIME}` (1h). |
| Traefik / cert-manager: no certificate metrics | Warning | An endpoint has not answered for `{$CERT.METRICS.NODATA}` (3h). |

Items:

- Two HTTP agent master items (`traefik.metrics.raw`, `certmanager.metrics.raw`), every 15 minutes, no history.
- LLD per Traefik CN (`traefik_tls_certs_not_after`). A CN that appears more than once (an old copy next to the renewed certificate) is reduced with `max`, so the old copy does not alert.
- LLD per cert-manager Certificate (`certmanager_certificate_expiration_timestamp_seconds`, `certmanager_certificate_ready_status`).

Thresholds can be set per certificate with macro context, e.g. `{$CERT.EXPIRY.WARN:"pb.noblia.se"}` or `{$CERT.EXPIRY.WARN:"bluemap-tls"}`. Retired names can be excluded with `{$TRAEFIK.CERT.CN.NOT_MATCHES}`.

## Requirements

- Traefik with `--metrics.prometheus=true` and a Service for the metrics port. The Helm chart only exposes it on the pod; this cluster uses `cluster2-k8sv2/helm/traefik/traefik-metrics-svc.yaml` (`traefik-metrics.traefik.svc:9100`).
- cert-manager with its default metrics Service (`cert-manager.cert-manager.svc:9402`).
- A host monitored by the in-cluster proxy (`zabbix-proxyv2`), for example the one with "Kubernetes cluster state by HTTP".

## Setup

1. Import `template/zbx_template_k8s_tls_certificates.yaml` (Data collection → Templates → Import).
2. Link "Kubernetes TLS certificates by HTTP" to the host monitored by the in-cluster proxy.
3. Run *Execute now* on the two master items, or wait 15 minutes, and check Latest data.
