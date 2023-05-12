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
