---
layout: default
title: IIS
parent: Checklists
---

# Усиление IIS для DevSecOps
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Список лучших практик по защите IIS для DevSecOps


### Отключить просмотр каталогов	 

```
Set-WebConfigurationProperty -filter /system.webServer/directoryBrowse -PSPath "IIS:\Sites\Default Web Site" -name enabled -value $false
```

### Удалите ненужные HTTP-заголовки 

```
Remove-WebConfigurationProperty -filter "system.webServer/httpProtocol/customHeaders" -name ."X-Powered-By"
```

### Установка безопасных заголовков HTTP-ответов 

```
Add-WebConfigurationProperty -filter "system.webServer/staticContent" -name "clientCache.cacheControlMode" -value "UseMaxAge"<br>Set-WebConfigurationProperty -filter "system.webServer/staticContent/clientCache" -name "cacheControlMaxAge" -value "365.00:00:00"<br>Add-WebConfigurationProperty -filter "system.webServer/httpProtocol/customHeaders" -name "X-Content-Type-Options" -value "nosniff"<br>Add-WebConfigurationProperty -filter "system.webServer/httpProtocol/customHeaders" -name "X-Frame-Options" -value "SAMEORIGIN"<br>Add-WebConfigurationProperty -filter "system.webServer/httpProtocol/customHeaders" -name "X-XSS-Protection" -value "1; mode=block"
```

### Включите HTTPS и настройте параметры SSL/TLS 

```
New-WebBinding -Name "Default Web Site" -Protocol https -Port 443 -IPAddress "*" -SslFlags 1<br>Set-ItemProperty -Path IIS:\SslBindings\0.0.0.0!443 -Name "SslFlags" -Value "1"<br>Set-WebConfigurationProperty -filter "system.webServer/security/authentication/iisClientCertificateMappingAuthentication" -name enabled -value $false<br>Set-WebConfigurationProperty -filter "system.webServer/security/authentication/anonymousAuthentication" -name enabled -value $false<br>Set-WebConfigurationProperty -filter "system.webServer/security/authentication/basicAuthentication" -name enabled -value $false<br>Set-WebConfigurationProperty -filter "system.webServer/security/authentication/digestAuthentication" -name enabled -value $false<br>Set-WebConfigurationProperty -filter "system.webServer/security/authentication/windowsAuthentication" -name enabled -value $true<br>Set-WebConfigurationProperty -filter "system.webServer/security/authentication/windowsAuthentication" -name useKernelMode -value $true
```

### Ограничение доступа к файлам и каталогам	 

```
Set-WebConfigurationProperty -filter "/system.webServer/security/requestFiltering/fileExtensions" -name "." -value @{allowed="$false"}<br>Set-WebConfigurationProperty -filter "/system.webServer/security/requestFiltering/hiddenSegments" -name "." -value @{allowed="$false"}<br>Set-WebConfigurationProperty -filter "/system.webServer/security/requestFiltering/denyUrlSequences" -name "." -value @{add="$false"}
```

### Включите ведение журнала и настройте параметры журнала	 

```
Set-WebConfigurationProperty -filter "/system.webServer/httpLogging" -name dontLog -value $false
```

или

```
Set-WebConfigurationProperty -filter "/system.webServer/httpLogging" -name logExtFileFlags -value "Date, Time, ClientIP, UserName, SiteName, ComputerName, ServerIP, Method, UriStem, UriQuery, HttpStatus, Win32Status, BytesSent, BytesRecv, TimeTaken 
```
