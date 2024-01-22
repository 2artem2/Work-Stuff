---
layout: default
title: GlusterFS
parent: Checklists
---

# Усиление GlusterFS для DevSecOps
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Список лучших практик по защите GlusterFS для DevSecOps


### Отключите небезопасные протоколы управления		 


```
gluster volume set <volname> network.remote-dio.disable on
```


### Включите SSL-шифрование для управления


```
gluster volume set <volname> network.remote.ssl-enabled on
```


### Ограничьте доступ для доверенных клиентов		


```
gluster volume set <том> auth.allow <comma-separated list of trusted IPs>
```


### Включите шифрование SSL на стороне клиента


```
gluster volume set <том> client.ssl on
```

### Включите аутентификацию для клиентских подключений	

```
gluster volume set <том> client.auth on
```

### Установите правильные разрешения для файлов и каталогов GlusterFS	

```
chown -R root:glusterfs /etc/glusterfs /var/lib/glusterd /var/log/glusterfs
```

### Отключить root-доступ к томам GlusterFS	

```
gluster volume set <том> auth.reject-unauthorized on
```

### Включите шифрование TLS для трафика GlusterFS	

```
gluster volume set <том> transport-type 
```


### Мониторинг журналов GlusterFS на предмет событий безопасности	

```
tail -f /var/log/glusterfs/glusterd.log
```
