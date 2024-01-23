---
layout: default
title: Weblogic
parent: Checklists
---

# Усиление Weblogic для DevSecOps
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Список лучших практик по защите Weblogic для DevSecOps


### Отключите учетные записи и пароли по умолчанию	  

```
wlst.sh $WL_HOME/common/tools/configureSecurity.py -removeDefaultConfig
``` 

### Используйте защищенный порт администрирования 

```
wlst.sh $WL_HOME/common/tools/configureSecurity.py -securityModel=OPSS -defaultRealm -realmName=myrealm -adminPortEnabled=true -adminPort=9002 -sslEnabled=true -sslListenPort=9003
```

### Обеспечение безопасной связи между серверами 

```
wlst.sh $WL_HOME/common/tools/configureSSL.py -action=create -identity keystore.jks -identity_pwd keystorepassword -trust keystore.jks -trust_pwd keystorepassword -hostName myhost.example.com -sslEnabledProtocols TLSv1.2 -enabledProtocols TLSv1.2 -keystoreType JKS -server SSL
``` 

### Включите безопасные соединения для источников данных JDBC 

```
wlst.sh $WL_HOME/common/tools/config/jdbc/SecureJDBCDataSource.py -url jdbc:oracle:thin:@//mydb.example.com:1521/HR -name myDataSource -user myuser -password mypassword -target myServer -trustStore myTrustStore.jks -trustStorePassword myTrustStorePassword -identityStore myIdentityStore.jks -identityStorePassword myIdentityStorePassword
```

### Ограничение доступа к консоли WebLogic 

Добавьте элементы `<security-constraint>` и `<login-config>` в файл `$DOMAIN_HOME/config/fmwconfig/system-jazn-data.xml`. 

### Включите протокол защищенных сокетов (SSL) для диспетчера узлов	 

```
wlst.sh $WL_HOME/common/tools/configureNodeManager.py -Dweblogic.management.server=http://myserver.example.com:7001 -Dweblogic.management.username=myusername -Dweblogic.management.password=mypassword -Dweblogic.NodeManager.sslEnabled=true -Dweblogic.NodeManager.sslHostnameVerificationIgnored=true -Dweblogic.NodeManager.KeyStores=CustomIdentityAndJavaTrust
```
