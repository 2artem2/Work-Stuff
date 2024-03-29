n---
layout: default
title: Maven
parent: Checklists
---

# Усиление Maven для DevSecOps
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Список лучших практик по защите Maven для DevSecOps


### Используйте Maven Central с HTTPS	

Настройте Maven на использование HTTPS при взаимодействии с репозиторием Maven Central, добавив следующее в ваш файл `settings.xml`:<br><br>`<mirrors><mirror><id>central</id><url>https://repo.maven.apache.org/maven2</url><mirrorOf>central</mirrorOf></mirror></mirrors>`



### Проверка PGP-подписей	


Загрузите файл .asc для каждой зависимости и плагина из Maven Central и проверьте его PGP-подпись с помощью команды gpg --verify.


### Ограничение доступа к хранилищу	

Предоставляйте доступ к хранилищу только доверенным пользователям и машинам. По возможности ограничьте доступ операциями записи.



### Использование частного репозитория

Создайте частный репозиторий Maven для хранения артефактов и зависимостей, которые не доступны публично. Это ограничивает риск загрузки скомпрометированных или вредоносных артефактов.


### Используйте обертку Maven

Используйте скрипт `mvnw` или скрипт `mvnw.cmd` в Windows вместо того, чтобы полагаться на установку Maven в масштабах всей системы. Это гарантирует, что во всех средах будет использоваться одна и та же версия Maven, и снижает риск конфликтов зависимостей.


### Сканирование на наличие уязвимостей

Используйте сканер зависимостей, например OWASP Dependency-Check или Snyk, для проверки известных уязвимостей в ваших зависимостях.


### Используйте принцип наименьших привилегий

Используйте принцип наименьших привилегий для ограничения прав доступа к процессу сборки Maven.



### Включение подробного протоколирования

Включите ведение подробного журнала в Maven, чтобы получать больше информации о процессе сборки. Это поможет диагностировать проблемы и обнаружить подозрительное поведение.



### Поддерживайте Maven в актуальном состоянии

Поддерживайте Maven и его плагины в актуальном состоянии, чтобы своевременно устранять уязвимости в системе безопасности.
