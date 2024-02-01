---
layout: default
title: Cloud
parent: Production
---

## Облачное сканирование
{: .no_toc }


## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---


Под сканированием облака в производстве DevSecOps понимает процесс постоянного сканирования производственной среды приложения, развернутого в облачной инфраструктуре, на предмет потенциальных уязвимостей и угроз безопасности. Это делается для того, чтобы приложение оставалось безопасным и соответствовало политикам и стандартам безопасности даже после его развертывания в облаке.

Инструменты облачного сканирования могут выполнять различные проверки безопасности производственной среды, включая сканирование уязвимостей, тестирование на проникновение и аудит соответствия. Эти инструменты помогают выявлять проблемы безопасности в режиме реального времени и предоставлять предупреждения и уведомления команде безопасности.

Некоторые преимущества облачного сканирования в производственном DevSecOps включают:

1. Мониторинг безопасности в реальном времени: Облачное сканирование позволяет командам безопасности контролировать производственную среду в режиме реального времени, обеспечивая раннее обнаружение и реагирование на потенциальные угрозы безопасности.

2. Автоматизированные проверки безопасности: Инструменты облачного сканирования могут быть интегрированы в конвейер DevOps для выполнения автоматических проверок безопасности производственной среды, что позволяет командам выявлять проблемы безопасности на ранних этапах цикла разработки.

3. Повышение соответствия требованиям: Инструменты облачного сканирования помогают обеспечить соответствие приложения отраслевым стандартам и нормам за счет непрерывного мониторинга производственной среды на предмет нарушений требований.

4. Снижение рисков: Облачное сканирование помогает снизить риск нарушения безопасности и других инцидентов безопасности за счет обнаружения и устранения потенциальных уязвимостей в производственной среде.




### CloudPassage Halo	


Инструмент, обеспечивающий видимость, безопасность и соответствие нормативным требованиям всей вашей облачной инфраструктуры.	


```
curl -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -X POST https://api.cloudpassage.com/v1/scans -d '{ "name": "Example Scan", "ip_address": "10.0.0.1", "port": 22, "option_profile": "pci"}'
```



## Облачное приложение

### AWS


- [ ] **Создание пользователя IAM**	

```
aws iam create-user --user-name <username>
```

- [ ] Прикрепление политики IAM к пользователю	

```
aws iam attach-user-policy --user-name <username> --policy-arn <policy-arn>
```

- [ ] Создание группы IAM	

```
aws iam create-group --group-name <group-name>
```

- [ ] Добавление пользователя в группу IAM	

```
aws iam add-user-to-group --user-name <username> --group-name <group-name>
```

- [ ] Создание роли IAM	

```
aws iam create-role --role-name <role-name> --assume-role-policy-document <trust-policy>
```

- [ ] Прикрепление политики IAM к роли	

```
aws iam attach-role-policy --role-name <role-name> --policy-arn <policy-arn>
```

- [ ] Включение MFA для пользователя IAM	

```
aws iam enable-mfa-device --user-name <username> --serial-number <mfa-serial-number> --authentication-code-one <code1> --authentication-code-two <code2>
```

- [ ] Создание группы безопасности	

```
aws ec2 create-security-group --group-name <group-name> --description <description> --vpc-id <vpc-id>
```

- [ ] Разрешение входящего трафика для группы безопасности	

```
aws ec2 authorize-security-group-ingress --group-id <group-id> --protocol <protocol> --port <port> --source <source>
```

- [ ] Создание списка контроля доступа к сети (NACL)	

```
aws ec2 create-network-acl --vpc-id <vpc-id>
```

- [ ] Добавьте правило для входящего потока в NACL	

```
aws ec2 create-network-acl-entry --network-acl-id <nacl-id> --rule-number <rule-number> --protocol <protocol> --rule-action <action> --cidr-block <cidr-block> --port-range From=<from-port>,To=<to-port>
```

- [ ] Создание AWS WAF WebACL	

```
aws wafv2 create-web-acl --name <acl-name> --scope <scope> --default-action <default-action>
```

- [ ] Связывание WebACL с ресурсом	

```
aws wafv2 associate-web-acl --web-acl-arn <acl-arn> --resource-arn <resource-arn>
```

- [ ] Включите AWS CloudTrail	

```
aws cloudtrail create-trail --name <trail-name> --s3-bucket-name <bucket-name>
```

- [ ] Создание правила настройки AWS	

```
aws configservice put-config-rule --config-rule <rule-definition>
```

- [ ] Включите AWS GuardDuty	

```
aws guardduty create-detector --enable
```

- [ ] Включить AWS Macie	

```
aws macie2 enable-macie
```

- [ ] Включите AWS SecurityHub	

```
aws securityhub enable-security-hub
```


#### Инспектор AWS	

Инструмент, анализирующий поведение и конфигурацию ресурсов AWS на предмет потенциальных проблем с безопасностью.	

```
aws inspector start-assessment-run --assessment-template-arn arn:aws:inspector:us-west-2:123456789012:target/0-nvgHXqLm/template/0-iMhM7g4p
```





### GCloud

- [ ] Создайте учетную запись службы	

```
gcloud iam service-accounts create <service-account-name> --display-name <display-name>
```

- [ ] Предоставление IAM-роли учетной записи службы	

```
gcloud projects add-iam-policy-binding <project-id> --member serviceAccount:<service-account-email> --role <role>
```

- [ ] Создайте правило брандмауэра	

```
gcloud compute firewall-rules create <rule-name> --network <network-name> --allow <protocol>:<port-range> --source-ranges <source-range>
```

- [ ] Включение журналов потоков VPC	

```
gcloud compute networks subnets update <subnet-name> --region <region> --enable-flow-logs --filter <filter-expression>
```

- [ ] Создание конфигурации уведомлений командного центра безопасности облака (Cloud SCC)	

```
gcloud scc notifications create <notification-config-id> --pubsub-topic <topic-name> --organization <organization-id> --filter <filter-expression>
```

- [ ] Включите API предотвращения потери данных (DLP)	

```
gcloud services enable dlp.googleapis.com
```

- [ ] Создание сканера облачной безопасности	

```
gcloud beta web-security-scanner scans create <scan-id> --target <target-url>
```

- [ ] Включите командный центр безопасности облака (Cloud SCC)	

```
gcloud services enable securitycenter.googleapis.com
```

- [ ] Создание ключа безопасности	

```
gcloud alpha cloud-shell ssh-key create
```

- [ ] Включите облачную броню	

```
gcloud compute security-policies create <policy-name> --description <description>
```

- [ ] Включите облачный прокси-сервер с учетом идентификационных данных (IAP)	

```
gcloud compute backend-services update <backend-service-name> --iap=enabled
```

- [ ] Создайте политику анализа состояния безопасности	

```
gcloud alpha security health-policies create <policy-name> --resource-type <resource-type> --filter <filter-expression>
```

- [ ] Включить двоичную авторизацию	

```
gcloud services enable binaryauthorization.googleapis.com
```

- [ ] Включите сканер безопасности облачных вычислений	

```
gcloud services enable securityscanner.googleapis.com
```


- [ ] Создание связки ключей в облачной службе управления ключами (KMS)	

```
gcloud kms keyrings create <keyring-name> --location <location>
```

- [ ] Создайте расписание сканирования облачных систем безопасности	

```
gcloud beta web-security-scanner scan-configs create <config-id> --schedule <schedule-expression> --target <target-url>
```

- [ ] Включите функцию предотвращения потери данных в облаке (DLP)	

```
gcloud services enable dlp.googleapis.com
```

- [ ] Создание командного центра безопасности облака (Cloud SCC) Источник	

```
gcloud scc sources create <source-id> --source <source-type> --resource <resource-name> --service-account <service-account-email>
```



#### Сканер безопасности облачных вычислений Google	


Инструмент, который сканирует ваше приложение App Engine на наличие распространенных веб-уязвимостей.	

```
gcloud beta app deploy --no-promote --version staging<br>gcloud beta app gen-config --custom<br>gcloud beta app deploy --config=cloudbuild.yaml --version=v1
```


### Azure

- [ ] Создайте группу ресурсов	

```
az group create --name <resource-group-name> --location <location>
```

- [ ] Создание виртуальной сети	

```
az network vnet create --name <vnet-name> --resource-group <resource-group-name> --subnet-name <subnet-name>
```

- [ ] Создание группы сетевой безопасности	

```
az network nsg create --name <nsg-name> --resource-group <resource-group-name>
```

- [ ] Создание правила группы сетевой безопасности	

```
az network nsg rule create --name <rule-name> --nsg-name <nsg-name> --resource-group <resource-group-name> --priority <priority> --protocol <protocol> --source-address-prefix <source-address> --destination-address-prefix <destination-address> --access <access> --direction <direction>
```

- [ ] Создание хранилища ключей	

```
az keyvault create --name <vault-name> --resource-group <resource-group-name> --location <location>
```

- [ ] Создание секрета хранилища ключей	

```
az keyvault secret set --name <secret-name> --vault-name <vault-name> --value <secret-value>
```

- [ ] Включите Центр безопасности Azure	

```
az security center pricing create --tier <pricing-tier> --resource-group <resource-group-name> --subscription <subscription-id>
```

- [ ] Обеспечение доступа к виртуальным машинам по принципу "точно в срок" (JIT)	

```
az security jit-policy create --name <policy-name> --resource-group <resource-group-name> --vm-name <vm-name>
```

- [ ] Включите брандмауэр Azure Firewall	

```
az network firewall create --name <firewall-name> --resource-group <resource-group-name> --location <location>
```

- [ ] Создание политики адаптивного контроля приложений Центра безопасности	

```
az security applocker-policy create --name <policy-name> --resource-group <resource-group-name> --location <location>
```


- [ ] Включите защиту идентификационных данных Azure Active Directory (AAD)	

```
az ad identity-protection enable --tenant-id <tenant-id>
```

- [ ] Включите Azure Sentinel	

```
az security workspace create --name <workspace-name> --resource-group <resource-group-name> --location <location>
```

- [ ] Создание центра безопасности Оценка соответствия нормативным требованиям	

```
az security regulatory-compliance-assessments create --name <assessment-name> --resource-group <resource-group-name> --standard-name <standard-name>
```

- [ ] Включите Azure Advanced Threat Protection (ATP)	

```
az security atp storage enable --resource-group <resource-group-name> --storage-account <storage-account-name>
```

- [ ] Включите Azure DDoS Protection	

```
az network ddos-protection create --name <protection-plan-name> --resource-group <resource-group-name> --location <location>
```

- [ ] Создание контакта безопасности центра безопасности	

```
az security contact create --name <contact-name> --resource-group <resource-group-name> --email <email-address>
```

- [ ] Включите защиту информации Azure	

```
az ad rms registration create --resource-group <resource-group-name> --tenant-id <tenant-id>
```

- [ ] Включите шифрование дисков Azure	

```
az vm encryption enable --name <vm-name> --resource-group <resource-group-name> --disk-encryption-keyvault <keyvault-name>
```

#### Центр безопасности Azure	

Инструмент, обеспечивающий защиту от угроз всех ваших сервисов и быстро развертываемый без необходимости управления инфраструктурой.	

```
az security assessment create --location westus --name "Example Assessment" --resource-group "MyResourceGroup" --scope /subscriptions/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/MyResourceGroup/providers/Microsoft.Compute/virtualMachines/myVM
```


## ScoutSuite

### Запустите ScoutSuite для облачного провайдера	

```
scout aws or scout azure or scout gcp
```

### Укажите конкретный регион для поставщика облачных услуг	

```
scout aws --region <region_name>
``` 

или 

```
scout azure --location <location_name>
```

или 

```
scout gcp --project <project_id> --region <region_name>
```

### Создайте отчет в формате JSON	

```
scout <provider> --report-dir <output_directory> --report-format json
```

### Создайте отчет в формате HTML	

```
scout <provider> --report-dir <output_directory> --report-format html
```

### Укажите имя выходного файла для отчета

```
scout <provider> --report-dir <output_directory> --report-format <format> --report-name <output_filename>
```


## Prowler

### Run Prowler	

```
python prowler.py
```

### Укажите профиль AWS	

```
python prowler.py --profile <profile_name>
```

### Укажите конкретный регион AWS	

```
python prowler.py --region <region_name>
```

### Выполнение определенных проверок/категорий	

```
python prowler.py --check <check_id> or python prowler.py --category <category_name>
```

### Вывод результатов в файл	

```
python prowler.py --file <output_file>
```

### Включите подробные выводы в выходные данные	

```
python prowler.py --findings
```

### Создайте отчет в формате HTML	

```
python prowler.py --html-report
```

### Создайте отчет в формате CSV	

```
python prowler.py --csv-report
```

### Создание XML-отчета JUnit	

```
python prowler.py --junit-xml
```

### Исключить конкретные проверки	

```
python prowler.py --exclude-check <check_id>
```

### Укажите пороговое значение уровня серьезности

```
python prowler.py --severity <severity_level>
```


## CCAT


### Запустить CCAT	

```
python ccat.py
```

### Укажите конкретный профиль AWS	

```
python ccat.py --profile <profile_name>
```

### Укажите конкретный регион AWS	

```
python ccat.py --region <region_name>
```

### Выполните специальные проверки	

```
python ccat.py --checks <check_id>
```

### Исключить конкретные проверки	

```
python ccat.py --exclude <check_id>
```

### Включите подробные выводы в выходные данные	

```
python ccat.py --findings
```

### Вывод результатов в файл	

```
python ccat.py --output-file <output_file>
```

### Создайте отчет в формате CSV	

```
python ccat.py --csv-report
```

### Создайте отчет в формате HTML	

```
python ccat.py --html-report
```

### Укажите пороговое значение уровня серьезности	

```
python ccat.py --severity <severity_level>
```





## SmogCloud


```
python3 smogcloud.py
Откройте веб-браузер и перейдите на сайт http://localhost:5000.
```

1. Просканируйте целевой URL-адрес на предмет распространенных ошибок конфигурации облака:   

Введите целевой URL-адрес в веб-интерфейсе и нажмите "Начать сканирование".

2. Просмотреть результаты сканирования и уязвимости:

Перейдите на страницу "Результаты" в веб-интерфейсе.

3. Выполните ручное тестирование на наличие определенных ошибок в конфигурации облака:

Следуйте инструкциям в веб-интерфейсе или файле README.

4. Сформируйте отчет о результатах сканирования:   

Нажмите "Сгенерировать отчет" в веб-интерфейсе.





