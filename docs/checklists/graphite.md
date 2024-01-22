---
layout: default
title: Graphite
parent: Checklists
---

# Усиление Graphite для DevSecOps
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Список лучших практик по защите Graphite для DevSecOps


### Отключить режим отладки	 


```
sed -i 's/DEBUG = True/DEBUG = False/g' /opt/graphite/webapp/graphite/local_settings.py
```


### Установите надежный секретный ключ для Django	


```
sed -i "s/SECRET_KEY = 'UNSAFE_DEFAULT'/SECRET_KEY = 'your-strong-secret-key-here'/g" /opt/graphite/webapp/graphite/local_settings.py
```


### Включить HTTPS



Установите SSL-сертификат и настройте NGINX на обслуживание Graphite по HTTPS



### Ограничение доступа к веб-интерфейсу Graphite



Настройте NGINX на требование аутентификации или ограничение доступа для определенных IP-адресов


### Ограничение доступа к API Graphite	

Настройте NGINX на требование аутентификации или ограничение доступа для определенных IP-адресов


### Отключите неиспользуемые компоненты Graphite		

Удалите неиспользуемые бэкенды кэша Carbon или приложения Django, чтобы уменьшить площадь атаки.


### Включите аутентификацию для приема данных Graphite	

Настройте Carbon на требование аутентификации для входящих данных


### Включите ведение журнала Graphite	

Настройте Graphite на ведение журнала доступа и сообщений об ошибках для облегчения поиска и устранения неисправностей



### Мониторинг метрик Graphite

Используйте инструмент мониторинга, например Prometheus или Nagios, чтобы отслеживать метрики Graphite и выявлять любые аномалии.





### Поддерживайте Graphite в актуальном состоянии

Регулярно обновляйте Graphite и его зависимости, чтобы устранить все известные уязвимости в системе безопасности.






