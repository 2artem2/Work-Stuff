---
layout: default
title: Squid
parent: Checklists
---

# Усиление Squid для DevSecOps
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Список лучших практик по защите Squid для DevSecOps


### Отключите метод HTTP TRACE


```
acl HTTP-methods method TRACE<br>http_access deny HTTP-methods
```


### Ограничение максимального размера объекта


```
maximum_object_size 1 MB
```


### Включить регистрацию доступа


```
access_log /var/log/squid/access.log
```


### Ограничение клиентских подключений


`acl clients src 192.168.1.0/24`<br>`http_access allow clients`<br>`http_max_clients 50`



### Ограничение разрешенных портов	


`acl Safe_ports port 80 443 8080`<br>`http_access deny !Safe_ports`
