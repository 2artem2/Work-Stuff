---
layout: default
title: Docker
parent: Checklists
---

# Усиление Docker для DevSecOps
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Список лучших практик по защите Docker для DevSecOps


### Включить доверие к содержимому Docker


```
export DOCKER_CONTENT_TRUST=1
```


### Ограничьте взаимодействие с демоном Docker локальным сокетом

```
sudo chmod 660 /var/run/docker.sock<br>sudo chgrp docker /var/run/docker.sock
```


### Включите режим Docker Swarm	
```
docker swarm init
```

### Настройка сетевой безопасности для Docker Swarm

```
docker network create --driver overlay my-network
```
### Реализуйте ограничения ресурсов для контейнеров Docker

```
docker run --cpu-quota=50000 --memory=512m my-image
```

### Используйте Docker Secrets для защиты конфиденциальных данных


```
docker secret create my-secret my-secret-data.txt
```


### Ограничение доступа к API Docker



Используйте обратный прокси-сервер, например NGINX или Apache, чтобы ограничить доступ к конечной точке Docker API.



### Регулярно обновляйте TLS-сертификаты Docker	


```
dockerd --tlsverify --tlscacert=ca.pem --tlscert=server-cert.pem --tlskey=server-key.pem -H=0.0.0.0:2376
```



### Используйте пользователя, не являющегося пользователем root	


```
user: <non-root-user>
```


### Ограничение возможностей контейнеров	


```
cap_drop: [CAP_SYS_ADMIN]
```


### Ограничение ресурсов контейнера	


```
resources:
	 limits:
	 	 cpus: 0.5
	 	 memory: 512M
```


### Включить файловую систему, доступную только для чтения	


```
read_only: true
```


### Установка политики перезапуска контейнера	


```
restart: unless-stopped
```


### Используйте TLS/SSL для безопасной связи	


```
docker run -d -p 443:443 --name registry -v /path/to/certs:/certs -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/domain.crt -e REGISTRY_HTTP_TLS_KEY=/certs/domain.key registry:latest
```



### Включить аутентификацию	


```
docker run -d -p 443:443 --name registry -v /path/to/auth:/auth -e REGISTRY_AUTH=htpasswd -e "REGISTRY_AUTH_HTPASSWD_REALM=Registry Realm" -e REGISTRY_AUTH_HTPASSWD_PATH=/auth/htpasswd registry:latest
```


### Ограничьте доступ для доверенных клиентов	


```
docker run -d -p 443:443 --name registry -e REGISTRY_HTTP_SECRET=mysecret registry:latest
```


### Внедрение политик контроля доступа	


```
docker run -d -p 443:443 --name registry -v /path/to/config.yml:/etc/docker/registry/config.yml registry:latest
```


### Включите функцию доверия к содержимому (подпись изображений)		


```
export DOCKER_CONTENT_TRUST=1
```




















