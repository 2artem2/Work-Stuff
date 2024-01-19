---
layout: default
title: Consul
parent: Checklists
---

# Усиление Consul для DevSecOps
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Список лучших практик для усиления Consul для DevSecOps


### Включите шифрование TLS для связи с Consul	


```
consul agent -config-dir=/etc/consul.d -encrypt=<encryption-key> -ca-file=/path/to/ca.crt -cert-file=/path/to/consul.crt -key-file=/path/to/consul.key
```


### Ограничение доступа к API Consul



```
consul acl bootstrap; consul acl policy create -name "secure-policy" -rules @secure-policy.hcl; consul acl token create -description "secure-token" -policy-name "secure-policy" -secret <secure-token>
```


### Ограничить ресурсы, выделяемые на обслуживание Consul	


`systemctl edit consul.service` и добавьте `CPUQuota=50%` и `MemoryLimit=512M`


### Отключите ненужные HTTP API


```
consul agent -disable-http-apis=stats
```


### Включение и настройка регистрации аудита

```
consul agent -config-dir=/etc/consul.d -audit-log-path=/var/log/consul_audit.log
```



### Включение и настройка проверок состояния


```
consul agent -config-dir=/etc/consul.d -enable-script-checks=true -script-check-interval=10s -script-check-timeout=5s -script-check-id=<check-id> -script-check=<check-command>
```




### Включите ограничение скорости для предотвращения DDoS-атак	

```
consul rate-limiting enable; consul rate-limiting config set -max-burst 1000 -rate 100
```




### Настройка процедур резервного копирования и восстановления данных Consul		


```
consul snapshot save /path/to/snapshot; consul snapshot restore /path/to/snapshot
```



