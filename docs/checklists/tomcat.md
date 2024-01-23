---
layout: default
title: Tomcat
parent: Checklists
---

# Усиление Tomcat для DevSecOps
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Список лучших практик по защите Tomcat для DevSecOps


### Отключение неиспользуемых разъемов

 Измените `server.xml`, чтобы удалить неиспользуемые коннекторы, например:

 ```
 <Connector port="8080" protocol="HTTP/1.1"
           connectionTimeout="20000"
           redirectPort="8443" />
 ```


### Используйте безопасную конфигурацию HTTPS

Измените `server.xml`, чтобы включить HTTPS и настроить SSL/TLS, например:

```
<Connector port="8443" protocol="HTTP/1.1" SSLEnabled="true"
           maxThreads="150" scheme="https" secure="true"
           clientAuth="false" sslProtocol="TLS" 
           keystoreFile="/path/to/keystore"
           keystorePass="password" />
```


### Отключение информации о версии на страницах ошибок

Измените файл `server.xml`, чтобы добавить следующий атрибут к элементу `<Host>`:

```
errorReportValveClass="org.apache.catalina.valves.ErrorReportValve" showReport="false" showServerInfo="false"
```


### Используйте безопасные настройки для менеджера и менеджера хоста

Измените `tomcat-users.xml`, чтобы добавить роли и пользователей с соответствующими правами, например:


```
<role rolename="manager-gui"/>
<user username="tomcat" password="password" roles="manager-gui"/>
```


### Используйте безопасные настройки для доступа к каталогам

Измените `context.xml`, чтобы добавить следующий элемент к элементу `<Context>`:


```
<Valve className="org.apache.catalina.valves.RemoteAddrValve" allow="127\.0\.0\.1|192\.168\.0\.\d+"/>
```


