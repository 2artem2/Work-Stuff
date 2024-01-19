---
layout: default
title: ArgoCD
parent: Checklists
---

# Усиление ArgoCD для DevSecOps
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Список лучших практик по укреплению ArgoCD для DevSecOps


### Отключите анонимный доступ к серверу API ArgoCD


```
argocd-server --disable-auth
```


### Включите HTTPS для связи с сервером ArgoCD



```
argocd-server --tls-cert-file /path/to/tls.crt --tls-private-key-file /path/to/tls.key
```


### Используйте надежный пароль для административных пользователей ArgoCD


```
argocd-server --admin-password <password>
```


### Ограничение доступа к серверу API ArgoCD по IP-адресу	


Измените конфигурационный файл `argocd-server`, указав опции `--client-ca-file` и `--auth-mode cert`, и создайте файл центра сертификации и клиентский сертификат, подписанный ЦС, для каждого клиентского узла.



### Включите RBAC для тонкого контроля доступа к ресурсам ArgoCD	

```
argocd-server --rbac-policy-file /path/to/rbac.yaml
```



### Настройка параметров безопасных файлов cookie для веб-интерфейса ArgoCD


```
argocd-server --secure-cookie
```




### Используйте принцип наименьших привилегий для доступа к API ArgoCD

Создайте специальную учетную запись службы ArgoCD с минимально необходимыми правами.



### Регулярно обновляйте ArgoCD до последней стабильной версии		


`argocd version --client` для проверки версии клиента и `argocd version --server` для проверки версии сервера. При необходимости используйте менеджер пакетов или обновляйте вручную.



### Регулярный аудит журналов ArgoCD и контроль доступа		


`argocd-server --loglevel debug`, чтобы включить ведение журнала на уровне отладки. Используйте анализатор журналов или инструмент SIEM для мониторинга журналов на предмет аномалий.



### Реализация плана резервного копирования и восстановления данных ArgoCD		


`argocd-util export /path/to/export` для экспорта данных и конфигурации ArgoCD. Храните резервные копии в безопасном месте и периодически проверяйте процедуру восстановления.

