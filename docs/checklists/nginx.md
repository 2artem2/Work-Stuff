---
layout: default
title: Nginx
parent: Checklists
---

# Усиление Nginx для DevSecOps
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Список лучших практик по защите Nginx для DevSecOps


### Отключите серверные токены	 

```
server_tokens off;
```

### Установите соответствующие разрешения на файлы 

`chmod 640 /etc/nginx/nginx.conf` или `chmod 440 /etc/nginx/nginx.conf` в зависимости от вашей установки 

### Внедрите SSL/TLS с соответствующими шифрами и протоколами 

`ssl_protocols TLSv1.2 TLSv1.3;` <br> `ssl_ciphers HIGH:!aNULL:!MD5;` 

### Включить HSTS 

```
add_header Strict-Transport-Security "max-age=31536000; includeSubdomains; preload";
```

### Настройка HTTP/2 

`listen 443 ssl http2;` 

### Ограничение доступа к определенным каталогам 

`location /private/ { deny all; }` 

### Отключите ненужные модули 

Закомментируйте или удалите неиспользуемые модули из файла `nginx.conf`. 

### Implement rate limiting 

```
limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;
```

### Реализуйте защиту от переполнения буфера 

`proxy_buffer_size 128k;` <br> `proxy_buffers 4 256k;` <br> `proxy_busy_buffers_size 256k;` 

### Реализуйте защиту от XSS 

`add_header X-XSS-Protection "1; mode=block";` 
