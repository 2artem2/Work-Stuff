---
layout: default
title: etcd
parent: Checklists
---

# Усиление etcd для DevSecOps
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Список лучших практик по защите etcd для DevSecOps


### Включите аутентификацию для etcd	 

```
etcd --auth-enable=true
```

### Настройка шифрования TLS для связи с etcd	

```
etcd --cert-file=/path/to/cert.pem --key-file=/path/to/key.pem --client-cert-auth=true --trusted-ca-file=/path/to/ca.pem
``` 

### Включите списки управления доступом (ACL) etcd.	


```
Enable etcd access control lists (ACLs)
```

### Ограничьте сетевой доступ к портам etcd	

```
iptables -A INPUT -p tcp --dport 2379 -j DROP
```
