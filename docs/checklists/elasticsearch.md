---
layout: default
title: Elasticsearch
parent: Checklists
---

# Усиление Elasticsearch для DevSecOps
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Список лучших практик по защите Elasticsearch для DevSecOps


### Отключите динамические скрипты и отключите встроенные скрипты	 


`sudo nano /etc/elasticsearch/elasticsearch.yml<br> Set the following configurations:<br>script.inline: false<br>script.stored: false<br>script.engine: "groovy"`



### Отключите неиспользуемые методы HTTP


`sudo nano /etc/elasticsearch/elasticsearch.yml` Добавьте следующую конфигурацию:<br>`http.enabled: true`<br>`http.cors.allow-origin: "/.*/"``http.cors.enabled: true`<br>`http.cors.allow-methods: HEAD,GET,POST,PUT,DELETE,OPTIONS`<br>`http.cors.allow-headers: "X-Requested-With,Content-Type,Content-Length"`<br>`http.max_content_length: 100mb`



### Ограничение доступа к портам Elasticsearch		

`sudo nano /etc/sysconfig/iptables`<br> Добавьте следующие правила, чтобы разрешить входящие соединения только с доверенных IP-адресов:<br>`-A INPUT -p tcp -m tcp --dport 9200 -s 10.0.0.0/8 -j ACCEPT`<br>`-A INPUT -p tcp -m tcp --dport 9200 -s 192.168.0.0/16 -j ACCEPT`<br>`-A INPUT -p tcp -m tcp --dport 9200 -j DROP`<br>Перезапустите службу iptables, чтобы применить изменения.<br>`sudo service iptables restart`



### Использование обратного прокси для защиты Elasticsearch	

Настройте обратный прокси (например, Nginx, Apache) перед Elasticsearch и настройте шифрование и аутентификацию SSL/TLS.

