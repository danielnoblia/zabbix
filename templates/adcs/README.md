# Microsoft Active Directory Certificate Services

## Description

Self-contained Zabbix template to get information about Microsoft Active Directory Certificate Services.

The template is based on this excellent article: [JSON is your friend – Certificate monitoring on Microsoft CA server](https://blog.zabbix.com/json-is-your-friend-certificate-monitoring-on-microsoft-ca-server/20697/)

I have modified it slightly to only retrieve information about specific certificate templates. Templates such as "Computer" can be excluded. To monitor multiple templates, simply create multiple host objects and bind the template to them.

## Overview

Self-contained Zabbix template to get information about Microsoft Active Directory Certificate Services.

## Author

Daniel Noblia
Tibor Volanszki


## Prerequisites
To start, you will need to deploy Zabbix agent 2 on your target system – confirm that the Zabbix agent can communicate with your Zabbix server.  For the calculated item, we will require local time monitoring. The easiest way is to use the key “system.localtime”, which is already provided by the default Windows OS monitoring template. This item is intentionally not included within the certificate monitoring template to avoid key conflicts.

Below you can find the Powershell script which you have to implement: (name: “certmon_get_certs.ps1″) :

To import module PSPKI you may have to install the module first: [PKI Solutions, PowerShell PKI Module ](https://pkisolutions.com/tools/pspki/). Download from [PowerShell PKI Module](https://github.com/PKISolutions/PSPKI)


## Agent Configuration

Agent configuration
To run the defined script, you have to allow it within the Zabbix Agent configuration file. You can either modify the main config or just define the extra lines within an additional file under zabbix_agent2.d folder. Below you can find the additional Zabbix agent configuration lines:

```ini
### Allow Key
AllowKey=system.run[powershell -NoProfile -ExecutionPolicy bypass -File "C:\Zabbix\Zabbix Agent 2\scripts\certmon_get_certs.ps1" *]
Timeout=20
```

The wildcard character at the end is needed to specify any hostname, which is expected by the script. The default timeout is 3 seconds, which is unfortunately insufficient. Importing Module PSPKI alone takes a few seconds, so the overall execution time is somewhere between 5 and 10 seconds. My assumption is that more certificates will not increase this significantly, but some extra seconds can be expected. 20 seconds sounds like a safe bet.

We are done with the pre-requisites, now we can start the real work!


One thing to note is that object **NotAfter** is returned differently in powershell version 5 versus version 7. It affects the script. If you are going to run powershell version 7, you need to redo the calculation of time.

|Powershell Version|Object:value|
|------------------|------|
|Powershell v7|"NotAfter":"2024-05-07T18:27:09"|
|Powershell v5|"NotAfter":"\/Date(1715099229000)\/"



## Powershell Script

```powershell
Import-Module PSPKI
$ca_hostname=$args[0]
$template=$args[1]
$start = (Get-Date).AddDays(-7)

$certcount = Get-IssuedRequest -CertificationAuthority srvoirca -Filter "NotAfter -ge $start", "CertificateTemplate -eq $template" |
    Group-Object -Property Request.RequesterName |
    ForEach-Object { $_.Group | Sort-Object NotAfter -Descending | Select-Object -First 1 }


If ($certcount.Count -Eq 1)
{
  ('[' + (Get-IssuedRequest -CertificationAuthority srvoirca -Filter "NotAfter -ge $start", "CertificateTemplate -eq $template" |
    Group-Object -Property Request.RequesterName |
    ForEach-Object { $_.Group | Sort-Object NotAfter -Descending | Select-Object -First 1 } |
    Select-Object -Property RequestID, Request.RequesterName, CommonName, NotAfter, CertificateTemplateOid |
    ConvertTo-Json -Compress) + ']')

} else {
    Get-IssuedRequest -CertificationAuthority srvoirca -Filter "NotAfter -ge $start", "CertificateTemplate -eq $template" |
    Group-Object -Property Request.RequesterName |
    ForEach-Object { $_.Group | Sort-Object NotAfter -Descending | Select-Object -First 1 } |
    Select-Object -Property RequestID, Request.RequesterName, CommonName, NotAfter, CertificateTemplateOid |
    ConvertTo-Json -Compress
}
```
*ConvertTo-Json does not return an array brackets if the response contains only one certificate. Therefore, you need to add []. 

*For Windows 2012 systems use CertificateTemplate instead of CertificateTemplateOid within this script.

This script expects two parameters, which is your CA server’s FQDN (or only host name) and the certificate template you want to monitor. That name will be loaded into variable "$ca_hostname". The second variable, "$template" dictates which certificate template you want to monitor. Based on your needs you can adjust the “AddDays” parameter. Essentially this means to track back certificates, which are already expired for up to 7 days. Consider a situation, when you miss one just before a long weekend. If multiple certificates are valid and issued to the same requester, the script only takes the most recent valid one.


## Macros used

|Name|Description|Default|Type|
|----|-----------|-------|----|
|{$CRT_WARNING}|<p>Warning trigger</p>|`20`|Text macro|
|{$CRT_CRITICAL}|<p>Critical trigger</p>|`5`|Text macro|
|{$CRT_HOSTNAME}|<p>Issuing certificate authority host name</p>|`is configured on the host and must be written in bubble quotes`|Text macro|
|{$CRT_TEMPLATE}|<p>Certifikat template to monitor</p>|`is configured on the device and must be written in bubble quotes`|Text macro|


## Template links

There are no template links in this template.

## Master Items

|Name|Description|Type|Key and additional info|
|----|-----------|----|----|
|Get certificate data|<p>Number of queries dropped because of a dynamic block.</p>|`Zabbix agent`|`system.run[powershell -NoProfile -ExecutionPolicy bypass -File "C:\Zabbix\Zabbix Agent 2\scripts\certmon_get_certs.ps1" {$CRT_HOSTNAME} {$CRT_TEMPLATE}]` <p>Update: `1h`</p>|


## Discovery rules

|Name|Description|Type|Key and additional info|
|----|-----------|----|----|
|Certificate discovery|<p>Dependent Item</p>|`Dependent Item`|`certificate.discovery`<p>Update: 6h</p>|

### LLD macros

|Name|Description|Default|Type|
|----|-----------|-------|----|
|{#COMMON_NAME}|<p> - </p>|`$.CommonName`|JSONPath|
|{#REQUESTOR_NAME}|<p> - </p>|`$.["Request.RequesterName"]`|JSONPath|
|{#REQUEST_ID}|<p> - </p>|`$.RequestID`|JSONPath|
|{#TEMPLATE_NAME2}|<p> - </p>|`$.CertificateTemplateOid.FriendlyName`|JSONPath|

### Item prototype 1

|Name|Description|Type|Key and additional info|
|----|-----------|----|----|
|Certificate [ ID #{#REQUEST_ID} ] {#COMMON_NAME} with {#TEMPLATE_NAME2} - Expiration date|<p> - </p>|`Dependent item`|`certificate.expiration_date[{#REQUEST_ID}]`|

#### Item tags 1

|Name|Description|Default|Type|
|----|-----------|-------|----|
|cert_requestor|<p> - </p>|`{{#REQUESTOR_NAME}.regsub("\\(\w+)", "\1")}`|
|cert_template2|<p> - </p>|`{#TEMPLATE_NAME2}`|
|scope|<p> - </p>|`certificate / expiration date`|

#### Preprocessing 1

|Name|Parameter 1|Parameter 2|
|----|-----------|-----------|
|JSOMPath|`$[?(@.RequestID == {#REQUEST_ID})].NotAfter`||
|Regular expression|`(\d+)`|`\1`|
|Custom multiplier|`0.001`||
|Discard unchanged with heartbeat|`1d`||


### Item prototype 2

|Name|Description|Type|Key and additional info|
|----|-----------|----|----|
|Certificate [ ID #{#REQUEST_ID} ] {#COMMON_NAME}  with {#TEMPLATE_NAME2} - Days to expire|<p> - </p>|`Calculated`|`certificate.remaining_days[{#REQUEST_ID}]`|

#### Item tags 2

|Name|Description|Default|Type|
|----|-----------|-------|----|
|cert_requestor|<p> - </p>|`{{#REQUESTOR_NAME}.regsub("\\(\w+)", "\1")}`|
|cert_template2|<p> - </p>|`{#TEMPLATE_NAME2}`|
|scope|<p> - </p>|`certificate / expiration date`|

#### Preprocessing 2

|Name|Parameter 1|Parameter 2|
|----|-----------|-----------|
|Regular expression|`^(-?\d+)`|`\1`|
|Discard unchanged with heartbeat|`1d`||

### Trigger prototypes 1

|Name|Description|Expression|Priority|
|----|-----------|----------|--------|
|Certificate will expire within {$CRT_CRITICAL} days – {#COMMON_NAME}|<p>-</p>|<p>**Expression**: `last(/Microsoft Certificate Authority Certificate monitoring Per CA Template/certificate.remaining_days[{#REQUEST_ID}])<={$CRT_CRITICAL}`</p><p>**Recovery expression**: </p>|high|

#### Trigger tags 1

|Name|Description|Default|Type|
|----|-----------|-------|----|
|cert_cn|<p> - </p>|`{#COMMON_NAME}`|
|cert_id|<p> - </p>|`{#REQUEST_ID}`|

### Trigger prototypes 2

|Name|Description|Expression|Priority|
|----|-----------|----------|--------|
|Certificate will expire within {$CRT_WARNING} days – {#COMMON_NAME}|<p>-</p>|<p>**Expression**: `last(/Microsoft Certificate Authority Certificate monitoring Per CA Template/certificate.remaining_days[{#REQUEST_ID}])<={$CRT_WARNING}`</p><p>**Recovery expression**: </p>|warning|

#### Trigger tags 2

|Name|Description|Default|Type|
|----|-----------|-------|----|
|cert_cn|<p> - </p>|`{#COMMON_NAME}`|
|cert_id|<p> - </p>|`{#REQUEST_ID}`|
