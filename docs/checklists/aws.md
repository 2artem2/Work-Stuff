---
layout: default
title: AWS
parent: Checklists
---

# Контрольный список безопасности AWS для DevSecOps
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Список лучших практик AWS для DevSecOps




### Включите многофакторную аутентификацию (MFA)

```
aws cognito-idp set-user-mfa-preference
```


### Установите строгую политику паролей

```
aws cognito-idp update-user-pool
```

### Включите расширенные функции безопасности      

```
aws cognito-idp set-user-pool-policy
```


### Ограничьте количество устройств, которые может запомнить пользователь 

```
aws cognito-idp set-device-configuration
```

### Установите тайм-аут сеанса для вашего пула пользователей    

```
aws cognito-idp update-user-pool-client
```

### Включите метод восстановления учетной записи 

```
aws cognito-idp set-account-recovery
```

### Отслеживайте и регистрируйте все события, связанные с входом и выходом из системы 

```
aws cognito-idp create-user-pool-domain
```

### Ограничьте доступ к своему пулу пользователей только из определенных диапазонов IP-адресов

```
aws cognito-idp update-resource-server
```
