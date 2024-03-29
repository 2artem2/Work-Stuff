---
layout: default
title: SaltStack
parent: Checklists
---

# Усиление SaltStack для DevSecOps
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Список лучших практик по укреплению SaltStack для DevSecOps


### Генерация SSL-сертификатов для связи с SaltStack

```
salt-call --local tls.create_self_signed_cert
```

### Включите SSL-шифрование для связи с SaltStack, обновив файл конфигурации мастера Salt

```
# /etc/salt/master
ssl_cert: /etc/pki/tls/certs/salt.crt
ssl_key: /etc/pki/tls/private/salt.key
``` 

### Отключение ненужных служб и открытие портов	

Отключите неиспользуемые службы и закройте ненужные порты на Salt Master и Salt Minions


### Ограничьте доступ к сети	

Настройте брандмауэры или сетевые ACL, чтобы разрешить доступ только из доверенных источников.


### Безопасное управление ключами Salt Minion

Правильное распределение, управление и защита ключей Salt Minion



### Внедрите надежную аутентификацию	

Используйте надежные пароли или аутентификацию на основе ключей для доступа к Salt Master и Minion


### Безопасный Salt Minions


- [x] Безопасное распространение и управление ключами Salt Minion.
- [x] Отключите ненужные службы и открытые порты на Salt Minions.
- [x] Ограничьте сетевой доступ к Salt Minions с помощью брандмауэров или сетевых ACL.
- [x] Включите механизмы аутентификации, такие как TLS/SSL, для безопасной связи.
- [x] Используйте надежные пароли или аутентификацию на основе ключей для доступа к Salt Minion.
- [x] Регулярно обновляйте Salt Minion до последней стабильной версии.
- [x] Включите протоколирование на Salt Minions и отслеживайте журналы на предмет событий безопасности.






