---
layout: default
title: auth0
parent: Checklists
---

# auth0 Контрольный список безопасности для DevSecOps
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Список лучших практик auth0 для DevSecOps




### Включите многофакторную аутентификацию (MFA) 

```
auth0 rules create --name enable-mfa
```


### Установите строгую политику паролей    

```
auth0 connections update
```

### Ограничение количества устройств                

```
Use Auth0 Dashboard to set device limits
```


### Включить обнаружение аномалий

```
auth0 anomaly enable
```

### Регулярная ротация клиентских секретов 

```
auth0 clients rotate-secret
```

### Ограничение разрешенных URL-адресов обратного вызова

```
auth0 clients update --callbacks
```

### Включите автоматический мониторинг журналов и оповещения  

```
Use Auth0 Dashboard to configure alerts
```


### Используйте контроль доступа на основе ролей (RBAC)  

```
auth0 roles create
```

