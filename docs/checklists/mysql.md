---
layout: default
title: MySQL
parent: Checklists
---

# Усиление MySQL для DevSecOps
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Список лучших практик по защите MySQL для DevSecOps


### Удалите тестовую базу данных и анонимного пользователя	


```
mysql -u root -p -e "DROP DATABASE IF EXISTS test; DELETE FROM mysql.user WHERE User=''; DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1'); FLUSH PRIVILEGES;"
```


### Ограничьте доступ для пользователя root	


```
mysql -u root -p -e "CREATE USER 'newuser'@'localhost' IDENTIFIED BY 'password'; GRANT ALL PRIVILEGES ON *.* TO 'newuser'@'localhost' WITH GRANT OPTION; FLUSH PRIVILEGES;"
```


### Включите кэш запросов	


```
mysql -u root -p -e "SET GLOBAL query_cache_size = 67108864; SET GLOBAL query_cache_type = ON;"
```


### Отключение удаленного входа в систему root	


Отредактируйте `/etc/mysql/mysql.conf.d/mysqld.cnf` и установите `bind-address` на IP-адрес сервера MySQL, затем перезапустите MySQL: `systemctl restart mysql`.


### Включите SSL для безопасных соединений		

Отредактируйте `/etc/mysql/mysql.conf.d/mysqld.cnf` и добавьте следующие строки: `ssl-ca=/etc/mysql/certs/ca-cert.pem` `ssl-cert=/etc/mysql/certs/server-cert.pem ssl-key=/etc/mysql/certs/server-key.pem` Затем перезапустите MySQL: `systemctl restart mysql`

