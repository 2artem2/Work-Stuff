---
layout: default
title: OpenShift
parent: Checklists
---

# Усиление OpenShift для DevSecOps
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Список лучших практик по защите OpenShift для DevSecOps


### Отключите небезопасные протоколы и шифры	

```
oc adm policy reconcile-cluster-role-binding
```

Включите аутентификацию и RBAC

```
oc adm policy add-cluster-role-to-user
```

Ограничение привилегированного доступа к кластеру	

```
oc adm policy add-scc-to-user
```

Включите ведение журнала аудита	

```
oc adm audit
```

Обеспечьте соблюдение лимитов и квот на ресурсы	


```
oc adm pod-network
```

Включите сетевые политики для изоляции	

```
oc create networkpolicy
```

Настройка безопасности времени выполнения контейнера	

```
oc adm policy add-scc-to-group
```

Безопасность etcd и основных узлов	

```
oc adm manage-node
```

Регулярное обновление и исправление компонентов OpenShift	

```
oc adm upgrade
```

Обеспечение подписи и проверки изображений	

```
oc image sign
```

Использование защищенного реестра для извлечения образов	

```
oc create secret
```

Включите шифрование данных в пути	

```
oc adm router
```

Повышение безопасности рабочих узлов	

```
oc adm manage-node
```

Внедрите многофакторную аутентификацию	

```
oc adm policy
```

Обеспечение централизованной регистрации и мониторинга	

```
oc adm logs
```
