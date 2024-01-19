---
layout: default
title: Apache
parent: Checklists
---

# Усиление Apache для DevSecOps
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Список лучших практик по защите Apache для DevSecOps


### Отключить листинг каталогов	 

```
Options -Indexes
```

### Включить подпись сервера 

```
ServerSignature On
``` 

### Отключить подпись сервера 

```
ServerSignature Off
```

### Изменение заголовка сервера 

```
ServerTokens Prod
```

### Отключить заголовок сервера 

`ServerTokens Prod` и `ServerSignature Off` 

### Включить HTTPS 

Установите SSL-сертификат и настройте Apache на его использование 

### Отключите метод HTTP TRACE 

```
TraceEnable off
```

### Установка безопасных заголовков HTTP-ответов 

```
Header always set X-XSS-Protection "1; mode=block"
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options SAMEORIGIN
Header always set Content-Security-Policy "default-src 'self'"
```
