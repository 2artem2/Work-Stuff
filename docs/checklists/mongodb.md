---
layout: default
title: MongoDB
parent: Checklists
---

# Усиление MongoDB для DevSecOps
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Список лучших практик по защите MongoDB для DevSecOps


### Отключить интерфейс HTTP


```
sed -i '/httpEnabled/ s/true/false/g' /etc/mongod.conf
```


### Включить аутентификацию	


```
sed -i '/security:/a \ \ \ \ authorization: enabled' /etc/mongod.conf
```


### Установите надежный пароль для пользователя admin	


```
mongo admin --eval "db.createUser({user: 'admin', pwd: 'new_password_here', roles: ['root']})"
```


### Отключите неиспользуемые сетевые интерфейсы	


```
sed -i '/net:/a \ \ \ \ bindIp: 127.0.0.1' /etc/mongod.conf
```


### Включить контроль доступа		


```
sed -i '/security:/a \ \ \ \ authorization: enabled' /etc/mongod.conf
```

### Включить шифрование SSL/TLS	

```
mongod --sslMode requireSSL --sslPEMKeyFile /path/to/ssl/key.pem --sslCAFile /path/to/ca/ca.pem --sslAllowInvalidHostnames
```

### Включите ведение журнала аудита	

```
sed -i '/systemLog:/a \ \ \ \ destination: file\n\ \ \ \ path: /var/log/mongodb/audit.log\n\ \ \ \ logAppend: true\n\ \ \ \ auditLog:\n\ \ \ \ \ \ \ \ destination: file\n\ \ \ \ \ \ \ \ format: JSON' /etc/mongod.conf
```

### Установите соответствующие разрешения на файлы	

```
chown -R mongodb:mongodb /var/log/mongodb<br>chmod -R go-rwx /var/log/mongodb
```

### Отключите неиспользуемые функции MongoDB	

```
sed -i '/operationProfiling:/a \ \ \ \ mode: off' /etc/mongod.conf<br>sed -i '/setParameter:/a \ \ \ \ quiet: true' /etc/mongod.conf
```


### Включите брандмауэры и ограничьте доступ к портам MongoDB	

```
ufw allow from 192.168.1.0/24 to any port 27017 proto tcp<br>ufw enable
```
