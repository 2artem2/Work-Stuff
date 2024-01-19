---
layout: default
title: CouchDB
parent: Checklists
---

# Усиление CouchDB для DevSecOps
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Список лучших практик по защите CouchDB для DevSecOps


### Отключить партию администраторов	 


Отредактируйте конфигурационный файл CouchDB `local.ini`, расположенный по адресу `/opt/couchdb/etc/couchdb/`. Измените строку `; [admins] на [admins]` и добавьте свое имя пользователя и пароль администратора. Сохраните и выйдите из файла. Перезапустите CouchDB. Пример команды: `sudo nano /opt/couchdb/etc/couchdb/local.ini`.


### Ограничьте доступ к конфигурационным файлам	

Измените владельца и группу каталога конфигурации CouchDB `/opt/couchdb/etc/couchdb/` на пользователя и группу CouchDB. Пример команды: `sudo chown -R couchdb:couchdb /opt/couchdb/etc/couchdb/`.


### Используйте шифрование SSL/TLS	

Создайте сертификаты SSL/TLS и настройте CouchDB на использование HTTPS. Пример команды для создания самоподписанных сертификатов: `sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/couchdb.key -out /etc/ssl/certs/couchdb.crt`.


### Ограничьте доступ к портам	

Используйте брандмауэр, чтобы ограничить доступ только к необходимым портам. Пример команды с использованием `ufw`: `sudo ufw allow from 192.168.1.0/24 to any port 5984`.


### Регулярно обновляйте CouchDB	

Регулярно устанавливайте обновления и патчи безопасности, чтобы обеспечить безопасность системы. Пример команды для обновления пакетов: `sudo apt-get update && sudo apt-get upgrade`.
