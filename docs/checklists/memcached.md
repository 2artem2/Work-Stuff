---
layout: default
title: Memcached
parent: Checklists
---

# Усиление Memcached для DevSecOps
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Список лучших практик по защите Memcached для DevSecOps


### Отключить UDP-приемник	


```
sed -i 's/^-U 0/#-U 0/g' /etc/sysconfig/memcached
```


### Включить аутентификацию SASL



`sed -i 's/^#-S/-S/g' /etc/sysconfig/memcached`<br>`yum install cyrus-sasl-plain`<br>`htpasswd -c /etc/sasl2/memcached-sasldb username`<br>`chmod 600 /etc/sasl2/memcached-sasldb`



### Ограничьте входящий трафик известными IP-адресами


```
iptables -A INPUT -p tcp --dport 11211 -s 192.168.1.100 -j ACCEPT
```


### Ограничьте максимальное использование памяти


```
echo 'CACHESIZE="128"' > /etc/sysconfig/memcached
```


### Запуск от имени пользователя, не являющегося пользователем root	

```
sed -i 's/^-u root/-u memcached/g' /etc/sysconfig/memcached
```



### Включить ведение журнала	

`sed -i 's/^logfile/#logfile/g' /etc/sysconfig/memcached`<br>`mkdir /var/log/memcached`<br>`touch /var/log/memcached/memcached.log`<br>`chown memcached:memcached /var/log/memcached/memcached.log`<br>`sed -i 's/^#logfile/LOGFILE="\/var\/log\/memcached\/memcached.log"/g' /etc/sysconfig/memcached`





### Обновление до последней версии	

```
yum update memcached
```




### Отключение неиспользуемых флагов		


`sed -i 's/^-I 1m/#-I 1m/g' /etc/sysconfig/memcached`<br>`sed -i 's/^-a 0765/#-a 0765/g' /etc/sysconfig/memcached`




