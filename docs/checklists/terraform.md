---
layout: default
title: Terraform
parent: Checklists
---

# Контрольный список безопасности Terraform для DevSecOps
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Список лучших практик использования Terraform для DevSecOps




### Включите подробное протоколирование аудита

```
terraform apply -var 'logging=true'
```


### Шифрование файлов состояния   

```
terraform apply -var 'encrypt=true'
```

### Используйте строгую политику доступа к внутренним ресурсам      

```
terraform apply -backend-config="..."
```


### Ограничьте права доступа к учетным записям автоматизации 

```
terraform apply -var 'permissions=limited'
```

### Регулярно меняйте секреты и ключи доступа    

```
terraform apply -var 'rotate_secrets=true'
```

### Использование ограничений по версиям в конфигурационных файлах 

```
terraform apply -var 'version=..."
```

### Проверьте файлы конфигурации перед применением 

```
terraform validate
```

### Регулярно обновляйте Terraform и провайдеров

```
terraform init -upgrade
```
