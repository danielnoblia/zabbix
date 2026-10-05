# MariaDB Operator Backup by HTTP

## Description

Zabbix template that alerts when scheduled [mariadb-operator](https://github.com/mariadb-operator/mariadb-operator) backups stop working.

A `Backup` resource with a `schedule` creates a Kubernetes CronJob with the same name. The template reads the CronJob status from kube-state-metrics, so it needs no extra accounts or changes in the cluster.

Background: backups failed silently for almost four months because the TLS certificate on the S3 endpoint had expired. The CronJob keeps only the latest failed job, so nothing looked wrong at a glance.

## What is checked

| Trigger | Severity | Fires when |
|---|---|---|
| Last scheduled run did not succeed | High | The last scheduled run is more than `{$BACKUP.RUN.GRACE}` old and `lastSuccessfulTime` is older than that run. For a nightly backup this fires about an hour after the failed run. |
| No successful backup for more than `{$BACKUP.MAX_AGE}`s | High | Nothing has succeeded for 26h. This catches a CronJob that is suspended, deleted or never scheduled. It depends on the trigger above, so a failed run is not reported twice. |
| No data from kube-state-metrics | Warning | The metrics endpoint has not answered for `{$KSM.NODATA}`. The other triggers depend on this one. |

Items:

* `mariadb.backup.last_success`: `kube_cronjob_status_last_successful_time`
* `mariadb.backup.last_schedule`: `kube_cronjob_status_last_schedule_time`
* `mariadb.backup.age`: seconds since the last successful run, for graphs

A missing metric is stored as `0`. Missing data then shows up as an old backup instead of an unsupported item. Manual jobs (`kubectl create job --from=cronjob/...`) update `lastSuccessfulTime` but not `lastScheduleTime`.

## Setup

1. Import `template/zbx_template_mariadb_operator_backup.yaml`.
2. Link it to the host that is monitored by the in-cluster Zabbix proxy, which is the host that has *Kubernetes cluster state by HTTP*. The HTTP agent item runs on the proxy and must be able to resolve `{$KSM.URL}`.
3. If needed, override the macros on the host.

## Macros

| Macro | Default | Description |
|---|---|---|
| `{$KSM.URL}` | `http://zabbix-kube-state-metrics.monitoring.svc.cluster.local:8080/metrics` | kube-state-metrics endpoint |
| `{$BACKUP.NAMESPACE}` | `db` | Namespace of the `Backup` resource |
| `{$BACKUP.CRONJOB}` | `backup` | CronJob name, which is the same as the `Backup` name |
| `{$BACKUP.MAX_AGE}` | `93600` | Seconds without a successful backup before alerting (26h) |
| `{$BACKUP.RUN.GRACE}` | `3600` | Seconds a run may take, including retries |
| `{$KSM.NODATA}` | `30m` | Time without data before the nodata trigger fires |

## Limitations

* The template covers one CronJob per host. To monitor several, link it to more hosts or rewrite it with low-level discovery.
* It confirms that the job reported success, not that the file exists in S3 or can be restored. A bucket-side check, such as age and size of the newest object, covers that.
