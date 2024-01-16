---
layout: default
title: Azure
parent: AiSecOps
---

# Azure 
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---






## Автоматизация соблюдения нормативных требований в Azure с помощью OpenAI



- [ ] Политика Azure

Azure Policy - это служба, позволяющая создавать, назначать и внедрять политики в среде Azure. Она помогает поддерживать соответствие требованиям, определяя и применяя правила и нормы.

```
az policy assignment create --name <assignment-name> --scope <scope> --policy <policy-definition-id>
```




- [ ] Центр безопасности Azure

Azure Security Center обеспечивает единое представление безопасности всех ресурсов Azure. Он предлагает рекомендации и предупреждения о безопасности, чтобы помочь вам выявить и устранить уязвимости в системе безопасности и проблемы с соблюдением нормативных требований.

```
az security assessment create --name <assessment-name> --resource-group <resource-group> --scopes <scopes> --standard-name <standard-name>
```





- [ ] Конвейеры Azure DevOps

Azure DevOps Pipelines - это платформа CI/CD, которая позволяет автоматизировать процессы сборки, тестирования и развертывания приложений и инфраструктуры.

```
- task: AzureCLI@2
  displayName: 'Run compliance check'
  inputs:
    azureSubscription: '<subscription>'
    scriptLocation: 'inlineScript'
    inlineScript: |
      # Выполните команду проверки соответствия здесь
```


## Логическая изоляция хранилища




- [ ] Учетные записи хранилищ Azure

Учетные записи хранения Azure обеспечивают масштабируемое и безопасное решение для хранения данных в Azure. Вы можете создать несколько учетных записей хранения, чтобы добиться логической изоляции данных.

```
az storage account create --name <storage-account-name> --resource-group <resource-group> --location <location> --kind StorageV2 --sku Standard_LRS
```



- [ ] Виртуальные сети Azure

Виртуальные сети Azure позволяют создавать изолированные сетевые среды в Azure. Вы можете связать свои учетные записи хранения с определенными виртуальными сетями, чтобы добиться логической изоляции сети.

```
az network vnet create --name <virtual-network-name> --resource-group <resource-group> --location <location> --address-prefixes 10.0.0.0/16
```



- [ ] Azure RBAC (управление доступом на основе ролей)

Azure RBAC позволяет управлять доступом к ресурсам Azure. Назначив соответствующие роли и разрешения, вы можете контролировать, кто имеет доступ к вашим учетным записям хранилища, и применять логический контроль доступа.

```
az role assignment create --assignee <user-or-group-id> --role <role-name> --scope <scope>
```




## Включите шифрование в состоянии покоя




- [ ] Шифрование службы хранения данных Azure

Служба Azure Storage Service Encryption автоматически шифрует данные, находящиеся в состоянии покоя в учетных записях Azure Storage. Она использует управляемые Microsoft ключи для обеспечения бесшовного шифрования без дополнительной настройки.

```
az storage account update --name <storage-account-name> --resource-group <resource-group> --encryption-services blob --encryption-key-type Account --encryption-key-source Microsoft
```



- [ ] Шифрование дисков Azure

Azure Disk Encryption позволяет шифровать диски с ОС и данными виртуальных машин Azure. Оно использует Azure Key Vault для безопасного хранения и управления ключами шифрования.

```
az vm encryption enable --name <vm-name> --resource-group <resource-group> --disk-encryption-keyvault <key-vault-name> --volume-type all
```



- [ ] Хранилище ключей Azure

Azure Key Vault - это централизованная облачная служба для управления и защиты криптографических ключей, сертификатов и секретов. Вы можете использовать Key Vault для управления ключами шифрования, используемыми для шифрования в состоянии покоя в Azure.

```
az keyvault create --name <key-vault-name> --resource-group <resource-group> --location <location>
```



## Шифрование в пути 




- [ ] Шлюз приложений Azure


Azure Application Gateway - это балансировщик нагрузки веб-трафика, который позволяет завершать SSL на шлюзе для обеспечения безопасной связи между клиентами и внутренними серверами.

```
az network application-gateway create --name <app-gateway-name> --resource-group <resource-group> --frontend-ip-name <frontend-ip-name> --http-settings-cookie-based-affinity Disabled --http-settings-protocol Https --frontend-port 443 --http-settings-port 443 --ssl-cert <ssl-cert-name> --servers <backend-server-ips> --sku Standard_v2 --public-ip-address <public-ip-name> --subnet <subnet-name> --vnet-name <vnet-name>
```



- [ ] Балансировщик нагрузки Azure

Балансировщик нагрузки Azure распределяет входящий сетевой трафик между несколькими ресурсами для повышения доступности и масштабирования приложений. Вы можете настроить балансировщик нагрузки с завершением SSL/TLS, чтобы обеспечить шифрование при передаче.

```
az network lb create --name <load-balancer-name> --resource-group <resource-group> --frontend-ip-name <frontend-ip-name> --backend-pool-name <backend-pool-name> --public-ip-address <public-ip-name> --protocol Tcp --frontend-port 443 --backend-port 443 --enable-tcp-reset --sku Standard
```



- [ ] Диспетчер трафика Azure

Azure Traffic Manager позволяет распределять входящий трафик между несколькими конечными точками в разных регионах или зонах доступности Azure. Он поддерживает завершение SSL/TLS на уровне Traffic Manager для обеспечения безопасной связи.

```
az network traffic-manager profile create --name <tm-profile-name> --resource-group <resource-group> --routing-method Priority --unique-dns-name <unique-dns-name> --protocol Https --port 443 --path /
```





## Ключи, управляемые клиентом




- [ ] Хранилище ключей Azure


Azure Key Vault - это облачная служба, которая позволяет вам защищать и контролировать криптографические ключи, секреты и сертификаты, используемые вашими приложениями и службами.

```
az keyvault create --name <key-vault-name> --resource-group <resource-group> --location <location>
```



- [ ] Шифрование дисков Azure



Azure Disk Encryption обеспечивает шифрование в состоянии покоя для дисков виртуальных машин с помощью ключей и секретов, хранящихся в Azure Key Vault.


```
az vm encryption enable --name <vm-name> --resource-group <resource-group> --disk-encryption-keyvault <key-vault-url> --volume-type [OS|Data] --volume-encryption-keyvault <key-vault-url>
```



- [ ] Набор шифрования дисков Azure


Набор шифрования дисков Azure - это группа управляемых дисков Azure, которые имеют одинаковые настройки и политики шифрования.

```
az disk encryption-set create --name <encryption-set-name> --resource-group <resource-group> --source-vault <key-vault-url> --encryption-key <encryption-key-url> --key-encryption-key <key-encryption-key-url>
```








