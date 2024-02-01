---
layout: default
title: Infrastructure
parent: Production
---

# Инфраструктура
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---


## Сервисная ячейка


### linkerd + istioctl

Шпаргалка по безопасности Linkerd:



- [ ] Вставьте прокси Linkerd's sidecar в YAML-файлы развертывания для автоматического mTLS.

```
linkerd --context <context> inject --manual <input.yaml> | kubectl apply -f -
```

- [ ] Включите mTLS для конкретного развертывания.

```
linkerd --context <context> -n <namespace> -o yaml tls web deployment/<deployment> | kubectl apply -f -
```
 

- [ ] Просматривайте трафик конкретного развертывания, отслеживая попытки несанкционированного доступа.

```
linkerd --context <context> -n <namespace> tap deploy/<deployment> --namespace=<target-namespace> --to <target-deployment> --method=<http-method>
```


- [ ] Наблюдение за трафиком и анализ потенциальных проблем, связанных с безопасностью, с помощью команды Linkerd's tap.

```
linkerd --context <context> -n <namespace> -o json tap deploy/<deployment> | jq . | less
```


- [ ] Установите Istio с включенным автоматическим mTLS.

```
istioctl --context <context> install --set profile=demo --set values.global.mtls.auto=true: 
```

- [ ] Создайте файлы манифеста Istio для текущей конфигурации.

```
istioctl --context <context> manifest generate | kubectl apply -f -: 
```

- [ ] Выполните проверку рукопожатия TLS для определенного хоста и пространства имен.

```
istioctl --context <context> authn tls-check <host> -n <namespace>: 
```


- [ ] Проверьте политики авторизации Istio для определенных потоков трафика.

```
istioctl --context <context> -n <namespace> authz check deploy/<deployment> --from <source-deployment> --to <target-deployment> --namespace=<target-namespace> --method=<http-method>
```


- [ ] Создайте файл захвата пакетов (PCAP) для конкретного стручка для углубленного анализа.

```
istioctl --context <context> -n <namespace> pcaps <pod-name> -o <output-file.pcap>
```

- [ ] Откройте Jaeger, распределенную систему трассировки, для визуализации и анализа запросов, отслеживаемых Istio.

```
istioctl --context <context> -n <namespace> dashboard jaeger
```

### Chaos


- [ ] Настройте Chaos Monkey

Отредактируйте файл `chaos.properties`, чтобы указать целевой сервис, частоту событий Chaos и другие настройки.

- [ ] Запустить Chaos Monkey	

```
./gradlew bootRun
```

- [ ] Убедитесь, что Chaos Monkey запущен	

Зайдите на приборную панель Chaos Monkey по адресу `http://localhost:8080/chaosmonkey`.

- [ ] Включите Chaos Monkey для определенной службы	

Установите свойство `chaos.monkey.enabled` в значение `true` для нужного сервиса в файле конфигурации.

- [ ] Отключите Chaos Monkey для определенной службы	

Установите свойство `chaos.monkey.enabled` в значение `false` для нужного сервиса в файле конфигурации.

- [ ] Настройте поведение Chaos Monkey 	

Измените свойства `chaos.monkey...` в файле конфигурации для определения событий Chaos, например `chaos.monkey.watcher.probablility` для настройки вероятности наступления события.


## Контейнер


- [ ] Запуск определенного бенчмарка

```
kube-bench --benchmark <benchmark-name>
```

- [ ] Создайте отчет в формате JSON для определенного бенчмарка

```
kube-bench --benchmark <benchmark-name> --json
```


- [ ] Запустите контрольные тесты от имени пользователя, не являющегося пользователем root

```
kube-bench --benchmark <benchmark-name> --run-as non-root
```

- [ ] Экспортируйте результаты бенчмарка в файл журнала.


```
kube-bench --benchmark <benchmark-name> --log <log-file>
```




### KubeLinter

Сканирование YAML-файлов Kubernetes:

```
kube-linter lint <path/to/kubernetes/yaml/files>
```


### Helm


- [ ] Проверка подписей диаграмм

Helm поддерживает подписание графиков с помощью криптографических подписей. Рекомендуется проверять подписи загружаемых графиков перед их развертыванием, чтобы убедиться, что они не были подделаны. Для проверки подписи графика можно использовать команду helm verify.

```
helm verify <chart-name>
```

- [ ] Ограничьте источники графиков

Чтобы свести к минимуму риск загрузки вредоносных или небезопасных графиков, лучше всего ограничить источники, из которых вы получаете графики. Вы можете настроить свои репозитории Helm так, чтобы они допускали только доверенные источники, изменив файл repositories.yaml.


```
helm repo list
helm repo remove <repository-name>
```

- [ ] Сканирование диаграмм на наличие уязвимостей

Перед развертыванием графика очень важно проверить его на наличие известных уязвимостей. Такие инструменты, как Trivy или Anchore Engine, помогут вам выполнить сканирование уязвимостей на графиках Helm.

```
trivy <chart-path>
```

- [ ] Включить RBAC


Helm позволяет включить управление доступом на основе ролей (RBAC), чтобы контролировать доступ к кластеру и ограничить круг лиц, которые могут выполнять операции Helm. Настройте правила RBAC, чтобы ограничить права пользователей Helm и гарантировать, что только авторизованные пользователи могут устанавливать или обновлять графики.

```
kubectl create role <role-name> --verb=<allowed-verbs> --resource=<allowed-resources>
kubectl create rolebinding <role-binding-name> --role=<role-name> --user=<user> --namespace=<namespace>
```


- [ ] Мониторинг релизов Helm

Регулярно следите за состоянием и изменениями в релизах Helm. Такие инструменты, как Helm Operator или Prometheus, помогут вам следить за состоянием и производительностью ваших развертываний Helm.

```
helm ls
```



- [ ] Сканирование диаграмм Helm с помощью Trivy

Trivy также может сканировать диаграммы Helm на наличие уязвимостей перед их развертыванием. Вот пример использования Trivy для сканирования диаграмм Helm:

```
trivy chart <chart-path>
```



### Checkov


- [ ] Сканирование файлов Terraform

```
checkov -d <path/to/terraform/files>: 
```

- [ ] Вывод результатов сканирования в формате JSON

```
checkov -o json: Generate scan results in JSON format.
```

- [ ] Игнорирование определенных идентификаторов проверок или путей к файлам

```
checkov --skip-check <check1,check2>: 
```



### Twistlock


- [ ] Подтяните образ сканера  Twistlock:

```
docker pull twistlock/scanner:latest: Pull the latest Twistlock Scanner image from Docker Hub.
```

- [ ] Сканирование образа Docker:

```
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock twistlock/scanner:latest <image-name>:<tag>: Perform a security scan on the specified Docker image.
```

- [ ] Проверка подлинности консоли Twistlock:

```
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock twistlock/scanner:latest --auth <console-url> --user <username> --password <password>: Authenticate the Twistlock Scanner with the Twistlock Console.
```

- [ ] Создайте HTML-отчет:

```
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock twistlock/scanner:latest --output-file <report-file.html> <image-name>:<tag>: Generate an HTML report for the scan results.
```

- [ ] Укажите политики сканирования:

```
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock twistlock/scanner:latest --policy-file <policy-file.yaml> <image-name>:<tag>: Use a custom policy file for the scan.
```




### Terrascan


- [ ] Сканирование файлов Terraform:

```
terrascan scan -i <путь/к/terraform/файлам>
```


- [ ] Укажите путь к политике

```
terrascan scan -p <путь/к/политике>
```


- [ ] Вывод результатов сканирования в формате JSON:

```
terrascan scan -f json
```

- [ ] Игнорируйте конкретные правила или ресурсы:

```
terrascan scan --skip-rules <rule1,rule2>
```


### Tfsec


- [ ] Сканирование файлов Terraform

```
tfsec <путь/к/terraform/файлам>
```


- [ ] Вывод результатов сканирования в формате JSON

```
tfsec --format=json: Generate scan results in JSON format.
```


- [ ] Игнорировать конкретные правила или предупреждения

```
tfsec --ignore <rule1,rule2>
```




## Сканирование инфраструктуры безопасности

Под сканированием инфраструктуры в производственном DevSecOps понимается процесс непрерывного сканирования базовой инфраструктуры приложения, развернутого в облачной инфраструктуре, на предмет потенциальных уязвимостей и угроз безопасности. Это делается для того, чтобы инфраструктура оставалась безопасной и соответствовала политикам и стандартам безопасности даже после ее развертывания в облаке.


### Nessus

Инструмент, который сканирует вашу сеть на наличие уязвимостей и предоставляет подробные отчеты.	


```
nessuscli scan new --policy "Basic Network Scan" --target "192.168.1.1"
```


### OpenVAS

Сканер уязвимостей с открытым исходным кодом, предоставляющий подробные отчеты и поддерживающий широкий спектр платформ.	

```
omp -u admin -w password -G "Full and fast" -T 192.168.1.1
```

### Qualys

Облачный инструмент для обеспечения безопасности и соответствия нормативным требованиям, который обеспечивает непрерывный мониторинг и подробную отчетность.	

```
curl -H "X-Requested-With: Curl" -u "username:password" "https://qualysapi.qualys.com/api/2.0/fo/scan/?action=launch&scan_title=Example Scan&target=192.168.1.1"
```

### Security Onion	

Дистрибутив Linux для обнаружения вторжений, мониторинга сетевой безопасности и ведения журналов.	

```
sudo so-import-pcap -r 2022-01-01 -c example.pcap
```

### Lynis

Инструмент для аудита безопасности в системах на базе Unix, который выполняет сканирование системы и предоставляет подробные отчеты.		

```
sudo lynis audit system
```

### Nuclei

Быстрый и настраиваемый сканер уязвимостей, поддерживающий широкий спектр платформ и технологий.	

```
nuclei -u http://example.com -t cves/CVE-2021-1234.yaml
```


### Шаблоны для Nuclei	

Коллекция шаблонов для Nuclei, охватывающая широкий спектр уязвимостей и неправильных конфигураций.	

```
nuclei -u http://example.com -t cves/ -max-time 5m
```

### Nuclei с Burp Suite	

Комбинация Nuclei и Burp Suite, позволяющая быстро сканировать и выявлять уязвимости в веб-приложениях.	

```
nuclei -t web-vulns -target http://example.com -proxy http://localhost:8080
```

### Nuclei с Masscan	

Комбинация Nuclei и Masscan, позволяющая быстро сканировать большие диапазоны IP-адресов и выявлять уязвимости.	

```
masscan -p1-65535 192.168.1.1-254 -oL ips.txt && cat ips.txt
```


### Определение защитных барьеров через HashiCorp

Применяет политики HashiCorp Sentinel для обеспечения соблюдения защитных барьеров, определенных в файле политики.

```
sentinel apply -policy=<policy_file>
```

### Сканирование уязвимостей с помощью nessuscli

Запускает проверку уязвимостей целевой системы с помощью Nessus.

```
nessuscli scan -t <target>
```

### Заплатка уязвимостей с помощью плейбука Ansible

Выполняет плейбук Ansible для исправления уязвимостей, указанных в плейбуке.

```
ansible-playbook -i inventory.ini patch_vulnerabilities.yml
```

### Проверка соответствия через aws-nuke

Удаляет ресурсы AWS, не соответствующие заданной конфигурации в файле конфигурации AWS Nuke.

```
aws-nuke --config=config.yml
```

### Непрерывный мониторинг соответствия через OPA

Оценивает политики Open Policy Agent (OPA) по входным данным для обеспечения соответствия требованиям.

```
opa eval -i <input_data> -d <policy_file>
```


## Туннель и прокси


### Nebula

Создает центр сертификации (ЦС) для Nebula с указанным именем и выводит файлы сертификата и ключа ЦС.

```
nebula-cert ca -name "<ca_name>" -out <ca_cert_file> -key <ca_key_file>
```

Подписывает сертификат узла с указанными файлами сертификата и ключей ЦС, именем узла, IP-адресом и выводит файл сертификата узла.

```
nebula-cert sign -ca-crt <ca_cert_file> -ca-key <ca_key_file> -name "<node_name>" -out <node_cert_file> -ip <node_ip>
```

Запускает узел Nebula с использованием указанного файла конфигурации

```
nebula -config <config_file>
```

Добавляет статический маршрут к узлу Nebula для указанной подсети назначения через указанный узел.

```
nebula route add -dst-subnet <destination_subnet> -via <via_node>
```

Запускает прокси-сервер Nebula, используя указанный файл конфигурации.

```
nebula-proxy -config <config_file>
```

Инициирует соединение с удаленным узлом с помощью оверлейной сети Nebula.

```
nebula connect <host_ip>
```

Проверяет состояние и возможность подключения узла Nebula.

```
nebula status
```

Отображает статистику и метрики узла Nebula.

```
nebula stats
```


### Chisel


Запускает сервер Chisel на указанном порту, обеспечивая обратное туннелирование.

```
chisel server -p <listen_port> --reverse
```

Запускает клиент Chisel и устанавливает обратный туннель к серверу Chisel. Он перенаправляет трафик с локального порта на удаленный хост и порт.

```
chisel client <server_host>:<server_port> R:<remote_host>:<remote_port>:<local_port>
```


Создает туннель от локального порта к удаленному хосту и порту через сервер Chisel. Флаг -f поддерживает соединение.

```
chisel client <server_host>:<server_port> -f -L <local_port>:<remote_host>:<remote_port>
```

Устанавливает локальный HTTP-прокси, который перенаправляет трафик на сервер Chisel и затем в интернет.

```
chisel client <server_host>:<server_port> -f -P <local_port>
```

Настройка локального SOCKS-прокси, который направляет трафик через сервер Chisel.


```
chisel client <server_host>:<server_port> -f -S <local_port>
```

Описание: 

Устанавливает обратный туннель и открывает локальный веб-сервис через сервер Chisel, используя протокол HTTP-прокси.

```
chisel client <server_host>:<server_port> --reverse --proxy-protocol http
```


Создает несколько туннелей от разных локальных портов к разным удаленным хостам и портам через сервер Chisel.

```
chisel client <server_host>:<server_port> -f -L <local_port1>:<remote_host1>:<remote_port1> -L <local_port2>:<remote_host2>:<remote_port2>
```


Проверяет подключение к серверу Chisel и отображает время в пути (RTT).

```
chisel client <server_host>:<server_port> --ping
```


## Управление инцидентами




### PagerDuty



```
import requests

def trigger_pagerduty_incident(service_key, description, details):
    url = "https://events.pagerduty.com/v2/enqueue"
    payload = {
        "routing_key": service_key,
        "event_action": "trigger",
        "payload": {
            "summary": description,
            "severity": "error",
            "source": "vulnerability-scanner",
            "custom_details": details
        }
    }
    headers = {
        "Content-Type": "application/json"
    }

    response = requests.post(url, json=payload, headers=headers)
    if response.status_code == 202:
        print("PagerDuty incident triggered successfully")
    else:
        print("Failed to trigger PagerDuty incident")

# Пример использования:
service_key = "YOUR_PAGERDUTY_SERVICE_KEY"
description = "Critical vulnerability detected"
details = {
    "scan_target": "example.com",
    "vulnerability_description": "CVE-2023-1234",
    "remediation_steps": "Update library version to 2.0.1"
}

trigger_pagerduty_incident(service_key, description, details)
```



В этом примере функция trigger_pagerduty_incident отправляет событие PagerDuty для запуска инцидента. Оно включает в себя краткое описание, степень серьезности, источник и пользовательские данные, такие как цель сканирования, описание уязвимости и предлагаемые шаги по устранению.


Затем мы определили три правила для инцидентов, основанных на различных приоритетах уязвимостей: Критический, Средний и Низкий. Каждое правило задает условие, основанное на поле приоритета, и если условие выполняется, запускаются соответствующие действия.

```
incident_rules:
  - name: Critical Vulnerability
    description: Notify the Security Team for critical vulnerabilities
    conditions:
      - field: priority
        operation: equals
        value: P1
    actions:
      - type: notify-team
        team: Security Team
        message: "Critical vulnerability detected. Please investigate and take immediate action."
      - type: add-note
        content: "Critical vulnerability detected. Incident created for further investigation."
  - name: Medium Vulnerability
    description: Notify the Development Team for medium vulnerabilities
    conditions:
      - field: priority
        operation: equals
        value: P2
    actions:
      - type: notify-team
        team: Development Team
        message: "Medium vulnerability detected. Please review and prioritize for remediation."
      - type: add-note
        content: "Medium vulnerability detected. Incident created for further review."
  - name: Low Vulnerability
    description: Notify the Operations Team for low vulnerabilities
    conditions:
      - field: priority
        operation: equals
        value: P3
    actions:
      - type: notify-team
        team: Operations Team
        message: "Low vulnerability detected. Please assess and plan for future updates."
      - type: add-note
        content: "Low vulnerability detected. Incident created for tracking and monitoring."
```



### Opsgenie


```
import requests

def create_opsgenie_alert(api_key, message, priority, details):
    url = "https://api.opsgenie.com/v2/alerts"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"GenieKey {api_key}"
    }
    payload = {
        "message": message,
        "priority": priority,
        "details": details
    }

    response = requests.post(url, json=payload, headers=headers)
    if response.status_code == 202:
        print("Opsgenie alert created successfully")
    else:
        print("Failed to create Opsgenie alert")

# Пример использования:
api_key = "YOUR_OPSGENIE_API_KEY"
message = "Critical vulnerability detected"
priority = "P1"
details = {
    "scan_target": "example.com",
    "vulnerability_description": "CVE-2023-1234",
    "remediation_steps": "Update library version to 2.0.1"
}

create_opsgenie_alert(api_key, message, priority, details)
```


В этом примере функция create_opsgenie_alert отправляет оповещение в Opsgenie, указывая сообщение, приоритет и дополнительные сведения, такие как цель сканирования, описание уязвимости и предлагаемые шаги по устранению.



Затем мы определили три правила для инцидентов, основанные на различных приоритетах уязвимостей: Критический, Средний и Низкий. Каждое правило задает условие, основанное на поле приоритета, и если условие выполняется, запускаются соответствующие действия.


```
rules:
  - name: Critical Vulnerability
    description: Notify the Security Team for critical vulnerabilities
    condition: priority == "P1"
    actions:
      - notify-team:
          name: Security Team
          message: "Critical vulnerability detected. Please investigate and take immediate action."
      - add-note:
          content: "Critical vulnerability detected. Incident created for further investigation."
  - name: Medium Vulnerability
    description: Notify the Development Team for medium vulnerabilities
    condition: priority == "P2"
    actions:
      - notify-team:
          name: Development Team
          message: "Medium vulnerability detected. Please review and prioritize for remediation."
      - add-note:
          content: "Medium vulnerability detected. Incident created for further review."
  - name: Low Vulnerability
    description: Notify the Operations Team for low vulnerabilities
    condition: priority == "P3"
    actions:
      - notify-team:
          name: Operations Team
          message: "Low vulnerability detected. Please assess and plan for future updates."
      - add-note:
          content: "Low vulnerability detected. Incident created for tracking and monitoring."
```




## Harbor

### Создайте новый проект в Harbor

```
curl -X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer <TOKEN>' -d '{"project_name": "myproject"}' https://<HARBOR_HOST>/api/v2.0/projects
```



### Добавьте нового пользователя в Harbor


```
curl -X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer <TOKEN>' -d '{"username": "newuser", "password": "password123"}' https://<HARBOR_HOST>/api/v2.0/users
```


### Сканирование изображения на наличие уязвимостей в Harbor


```
curl -X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer <TOKEN>' -d '{"registry": "https://<REGISTRY_HOST>", "repository": "myimage", "tag": "latest"}' https://<HARBOR_HOST>/api/v2.0/scan
```


### Удаление проекта в Harbor

```
curl -X DELETE -H 'Authorization: Bearer <TOKEN>' https://<HARBOR_HOST>/api/v2.0/projects/myproject
```


### Получение списка репозиториев в Harbor

```
curl -H 'Authorization: Bearer <TOKEN>' https://<HARBOR_HOST>/api/v2.0/repositories
```



## Clair


### Сканирование образа Docker с помощью Clair

```
clairctl analyze -l <image_name>
```



### Получение отчета об уязвимостях для образа Docker из Clair


```
clairctl report -l <image_name>
```




### Обновление базы данных уязвимостей в Clair


```
clairctl update
```



### Удаление образа Docker из базы данных Clair


```
clairctl delete -l <image_name>
```



### Получение сведений об уязвимости для конкретного CVE в Clair


```
clairctl vulnerability <CVE_ID>
```


## Podman

### Запустите контейнер в режиме без рута

```
podman run --rm -it --userns=keep-always <имя_образа>
```


### Включите профиль seccomp для контейнера


```
podman run --rm -it --security-opt seccomp=/path/to/seccomp.json <имя_образа>
```


### Применить контекст SELinux к контейнеру


```
podman run --rm -it --security-opt label=type:container_runtime_t <имя_образа>
```


### Настройте профиль AppArmor для контейнера


```
podman run --rm -it --security-opt apparmor=docker-default <имя_образа>
```


### Включите корневую файловую систему контейнера, доступную только для чтения


```
podman run --rm -it --read-only <имя_образа>
```


## skopeo


### Копирование образа из одного реестра контейнеров в другой с проверкой его подлинности:

```
skopeo copy --src-creds=<source_credentials> --dest-creds=<destination_credentials> --src-tls-verify=true --dest-tls-verify=true docker://<source_registry>/<source_image>:<tag> docker://<destination_registry>/<destination_image>:<tag>
```




### Осмотрите манифест изображения, чтобы просмотреть его детали и убедиться в его целостности:


```
skopeo inspect --tls-verify=true docker://<registry>/<image>:<tag>
```




### Копирование образа из реестра контейнеров в локальную файловую систему с проверкой его подписи:


```
skopeo copy --src-creds=<source_credentials> --dest-tls-verify=true docker://<registry>/<image>:<tag> oci:<destination_directory>
```




### Список тегов, доступных для определенного образа в реестре контейнеров:


```
skopeo list-tags --tls-verify=true docker://<registry>/<image>
```





### Удалить образ из реестра контейнеров:



```
skopeo delete --creds=<registry_credentials> --tls-verify=true docker://<registry>/<image>:<tag>
```




## Open Containers Initiative (OCI)


### Проверка целостности образа



```
import (
    "fmt"
    "github.com/opencontainers/go-digest"
    "github.com/opencontainers/image-spec/specs-go/v1"
)

func verifyImageIntegrity(manifest v1.Manifest) error {
    for _, layer := range manifest.Layers {
        if layer.MediaType == "application/vnd.oci.image.layer.v1.tar" {
            digest := layer.Digest
            // Проверьте целостность слоя с помощью дайджеста
            isValid, err := verifyLayerDigest(digest)
            if err != nil {
                return err
            }
            if !isValid {
                return fmt.Errorf("Layer integrity check failed")
            }
        }
    }
    return nil
}

func verifyLayerDigest(digest digest.Digest) (bool, error) {
    // Реализуйте логику для проверки дайджеста на соответствие хранимому слою
    // Возвращаем true, если дайджест валиден, false в противном случае
}
```


### Сканирование уязвимостей с помощью изображений:




```
import (
    "fmt"
    "github.com/opencontainers/image-spec/specs-go/v1"
)

func enforceVulnerabilityScanning(manifest v1.Manifest) error {
    for _, annotation := range manifest.Annotations {
        if annotation.Name == "com.example.vulnerability-scanning" && annotation.Value != "enabled" {
            return fmt.Errorf("Vulnerability scanning is not enabled for the image")
        }
    }
    return nil
}
```


### Внедрите функцию подписи изображений:




```
import (
    "fmt"
    "github.com/opencontainers/image-spec/specs-go/v1"
)

func signImage(manifest v1.Manifest, privateKey string) error {
    // Используйте закрытый ключ для подписи изображения.
    // Верните ошибку, если подписание не удалось
}
```


### Обеспечьте доверие к содержимому изображений:




```
import (
    "fmt"
    "github.com/opencontainers/image-spec/specs-go/v1"
)

func enforceContentTrust(manifest v1.Manifest) error {
    for _, annotation := range manifest.Annotations {
        if annotation.Name == "com.example.content-trust" && annotation.Value != "true" {
            return fmt.Errorf("Content trust is not enabled for the image")
        }
    }
    return nil
}
```


### Безопасная передача изображений:




```
import (
    "fmt"
    "github.com/opencontainers/image-spec/specs-go/v1"
)

func secureImageTransmission(manifest v1.Manifest) error {
    for _, layer := range manifest.Layers {
        if layer.MediaType == "application/vnd.oci.image.layer.v1.tar" {
            // Реализуйте логику, обеспечивающую безопасную передачу слоя.
            // Верните ошибку, если передача не является безопасной
        }
    }
    return nil
}
```




## API Umbrella и Kong


### Ограничение тарифов


```
curl -X PUT \
  -H "Content-Type: application/json" \
  -H "X-Admin-Auth-Token: YOUR_ADMIN_AUTH_TOKEN" \
  -d '{
    "settings": {
      "rate_limit_mode": "custom",
      "rate_limits": [
        {
          "duration": 1,
          "limit_by": "ip",
          "limit": 100
        }
      ]
    }
  }' \
  https://your-api-umbrella-host/admin/api/settings
```





### Аутентификация и авторизация


```
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "name": "jwt-auth",
    "config": {
      "uri_param_names": ["token"],
      "secret_is_base64": false
    },
    "plugin": "jwt"
  }' \
  http://localhost:8001/services/{service_id}/plugins
```





### Завершение работы SSL/TLS


```
curl -X PUT \
  -H "Content-Type: application/json" \
  -H "X-Admin-Auth-Token: YOUR_ADMIN_AUTH_TOKEN" \
  -d '{
    "frontend_host": "your-api.example.com",
    "backend_protocol": "https",
    "backend_ssl_cert": "YOUR_SSL_CERT",
    "backend_ssl_key": "YOUR_SSL_KEY"
  }' \
  https://your-api-umbrella-host/admin/api/services/{service_id}
```





### Ведение журнала и мониторинг


```
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{
    "name": "file-log",
    "config": {
      "path": "/var/log/kong/access.log"
    },
    "plugin": "file-log"
  }' \
  http://localhost:8001/services/{service_id}/plugins
```





### Управление ключами API


```
curl -X POST \
  -H "Content-Type: application/json" \
  -H "X-Admin-Auth-Token: YOUR_ADMIN_AUTH_TOKEN" \
  -d '{
    "api_key": {
      "user_id": "your-user-id",
      "key": "your-api-key",
      "created_at": "2022-01-01T00:00:00Z"
    }
  }' \
  https://your-api-umbrella-host/admin/api/api_keys
```





## Argo CD


### Включите аутентификацию для Argo CD с помощью OIDC (OpenID Connect)

```
# rbac-config.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: argocd-admin
  namespace: argocd
subjects:
- kind: User
  name: <username>
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: ClusterRole
  name: admin
  apiGroup: rbac.authorization.k8s.io
```



### Включите шифрование SSL/TLS для  Argo CD

```
# values.yaml
сервер:
  config:
    tls.enabled: true
    tls.insecure: false
    tls.crt: |
      -----BEGIN CERTIFICATE-----
      <Ваш_сертификат_здесь>.
      -----END CERTIFICATE-----
    tls.key: |
      -----BEGIN PRIVATE KEY-----
      <ваш_приватный_ключ_здесь>
      -----END PRIVATE KEY-----
```



### Ограничение доступа к API-серверу Argo CD с помощью сетевых политик

```
# network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: argocd-network-policy
  namespace: argocd
spec:
  podSelector: {}
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: <allowed_namespace>
```


### Включите аутентификацию Webhook для Argo CD

```
# values.yaml
server:
  config:
    repository.credentials:
    - name: <repo_name>
      type: helm
      helm:
        url: <helm_repo_url>
        auth:
          webhook:
            url: <webhook_url>
            secret: <webhook_secret>
```








## flux2


### Включите RBAC (контроль доступа на основе ролей) для Flux

```
# flux-system-rbac.yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: flux-system-rbac
subjects:
- kind: ServiceAccount
  name: flux-system
  namespace: flux-system
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
```




### Обеспечение сканирования изображений с помощью Trivy для рабочих нагрузок Flux

```
# flux-system-policies.yaml
apiVersion: image.toolkit.fluxcd.io/v1alpha2
kind: Policy
metadata:
  name: flux-system-policies
  namespace: flux-system
spec:
  policyType: tag
  repositories:
  - name: <repository_name>
    imagePolicy:
      name: trivy
      enabled: true
      args:
        - "--severity"
        - "HIGH,CRITICAL"
```





### Используйте GitOps для управления секретами Kubernetes с помощью Flux

```
# secrets.yaml
apiVersion: v1
kind: Secret
metadata:
  name: <secret_name>
  namespace: <namespace>
stringData:
  <key>: <value>
```





### Настройка многопользовательских отношений с Flux с помощью веток Git

```
# flux-system-repo.yaml
apiVersion: source.toolkit.fluxcd.io/v1alpha2
kind: GitRepository
metadata:
  name: flux-system-repo
  namespace: flux-system
spec:
  url: <repository_url>
  ref:
    branch: <branch_name>
  interval: 1m
```





### Обеспечение автоматического масштабирования кластера с помощью Flux и Kubernetes Horizontal Pod Autoscaler (HPA)

```
# flux-system-autoscaler.yaml
apiVersion: autoscaling/v2beta2
kind: HorizontalPodAutoscaler
metadata:
  name: <hpa_name>
  namespace: <namespace>
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: <deployment_name>
  minReplicas: <min_replicas>
  maxReplicas: <max_replicas>
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: <cpu_utilization>
```








## GoCD


### Включите SSL/TLS для сервера GoCD

```
<server>
  <!-- Other server configuration settings -->

  <ssl>
    <keystore>/path/to/keystore.jks</keystore>
    <keystore-password>keystore_password</keystore-password>
    <key-password>key_password</key-password>
  </ssl>
</server>
```



### Внедрение управления доступом на основе ролей (RBAC)

```
curl -u <admin_username>:<admin_password> -H 'Content-Type: application/json' -X POST \
  -d '{
    "name": "Developers",
    "users": ["user1", "user2"],
    "pipelines": {
      "read": ["pipeline1", "pipeline2"]
    }
  }' \
  http://localhost:8153/go/api/admin/security/roles
```

### Настройка интеграции с LDAP или Active Directory

```
<security>
  <!-- Other security settings -->

  <ldap uri="ldap://ldap.example.com:389" managerDn="cn=admin,dc=example,dc=com" managerPassword="password">
    <loginFilter>(uid={0})</loginFilter>
    <searchBases>ou=users,dc=example,dc=com</searchBases>
    <loginAttribute>uid</loginAttribute>
    <searchUsername>uid=admin,ou=users,dc=example,dc=com</searchUsername>
    <searchPassword>password</searchPassword>
  </ldap>
</security>
```

### Внедрите двухфакторную аутентификацию (2FA)

```
<security>
  <!-- Other security settings -->

  <authConfigs>
    <authConfig id="google_auth" pluginId="cd.go.authentication.plugin.google.oauth">
      <property>
        <key>ClientId</key>
        <value>your_client_id</value>
      </property>
      <property>
        <key>ClientSecret</key>
        <value>your_client_secret</value>
      </property>
    </authConfig>
  </authConfigs>
</security>
```

### Включение сканирования безопасности агентов GoCD

```
pipeline:
  stages:
    - name: Build
      # Конфигурация этапа сборки

    - name: SonarQube
      jobs:
        - name: RunSonarQube
          tasks:
            - exec: sonar-scanner
```




## Calico

### Включите сетевые политики Calico  

```
kubectl apply -f calico-policy.yaml
```


### Проверьте сетевые политики Calico    

```
kubectl get networkpolicies
```


### Посмотреть журналы Calico    

```
kubectl logs -n kube-system <calico-pod-name>
```


### Сетевая политика для запрета всего входящего трафика:


```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-ingress
spec:
  podSelector: {}
  policyTypes:
  - Ingress
```


### Сетевая политика для разрешения входящего трафика из определенного пространства имен:


```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-ingress-from-namespace
spec:
  podSelector: {}
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: allowed-namespace
```

### Сетевая политика для разрешения исходящего трафика на определенный IP или диапазон IP:


```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-egress-to-ip-range
spec:
  podSelector: {}
  egress:
  - to:
    - ipBlock:
        cidr: 10.0.0.0/24
```

### Сетевая политика для принудительного использования меток подкачки:


```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: enforce-pod-labels
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
```

### Сетевая политика для обеспечения безопасности сети на основе eBPF:


```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: enforce-ebpf-security
spec:
  podSelector: {}
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          calico/knsname: kube-system
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          calico/knsname: kube-system
```




## AWS CloudFormation Guard

### Создание файла правил охраны    

```
cfn-guard init <rule-file-name>.ruleset
```


### Оценка шаблона CloudFormation на соответствие правилам Guard  

```
cfn-guard validate -t <template-file> -r <rule-file>
```

### Создайте шаблон с условиями Guard   


```
cfn-guard generate -t <template-file> -r <rule-file> -o <output-file>
```

### Включить подробный вывод результатов оценки    

```
cfn-guard validate -t <template-file> -r <rule-file> --verbose
```


### Запуск Guard с пользовательской конфигурацией 


```
cfn-guard validate -t <template-file> -r <rule-file> --config <config-file>
```


### Проверьте, разрешен ли тип экземпляра EC2:



```
rules:
  - id: ec2InstanceTypeRule
    description: Check allowed EC2 instance types
    matches:
      - resources:
          - MyEC2Instance
        properties:
          instanceType:
            notEquals: t2.micro
```




### Применять маркировку для ведра S3:



```
rules:
  - id: s3BucketTaggingRule
    description: Enforce tagging for S3 buckets
    matches:
      - resources:
          - MyS3Bucket
        properties:
          tags:
            notPresent: "my-tag"
```



### Убедитесь, что используется определенный диапазон VPC CIDR:



```
cfn-guard validate -t <template-file> -r <rule-file> --config <config-file>
```




### Убедитесь, что используется определенный диапазон VPC CIDR:
 


```
rules:
  - id: vpcCIDRRule
    description: Ensure a specific VPC CIDR range is used
    matches:
      - resources:
          - MyVPC
        properties:
          cidrBlock:
            equals: 10.0.0.0/16
```




### Ограничьте использование небезопасных групп безопасности:



```
rules:
  - id: securityGroupRule
    description: Restrict the use of insecure security groups
    matches:
      - resources:
          - MySecurityGroup
        properties:
          securityGroupIngress:
            notMatches:
              - cidrIp: 0.0.0.0/0
                ipProtocol: -1
```




### Убедитесь, что для экземпляра RDS включено шифрование:



```
rules:
  - id: rdsEncryptionRule
    description: Ensure encryption is enabled for RDS instances
    matches:
      - resources:
          - MyRDSInstance
        properties:
          storageEncrypted:
            equals: true
```

## kube-green


### Проверка состояния определенного ресурса в кластере    

```
kube-green check RESOURCE_NAME
```


### Проверьте состояние всех ресурсов в определенном пространстве имен      

```
kube-green check -n NAMESPACE
```


### Проверка работоспособности определенного ресурса с заданным таймаутом      

```
kube-green check --timeout TIMEOUT RESOURCE_NAME
```


### Получите подробную информацию о состоянии здоровья конкретного ресурса   

```
kube-green describe RESOURCE_NAME
```


### Следите за состоянием здоровья определенного типа ресурсов в кластере в режиме реального времени    

```
kube-green watch --kind RESOURCE_TYPE
```


### Мониторинг состояния здоровья ресурсов в пространстве имен Kubernetes и отправка уведомлений на канал Slack:

    
```
kube-green monitor --namespace <namespace> --notifications slack --slack-channel #channel-name
```

### Мониторинг состояния здоровья ресурсов в пространстве имен Kubernetes и отправка уведомлений на канал Microsoft Teams:


```
kube-green monitor --namespace <namespace> --notifications teams --teams-channel #channel-name
```




## Regula


### Сканирование каталога на предмет нарушений нормативных требований    

```
regula scan -d <directory-path>
```

### Сканирование определенного файла на предмет нарушения нормативных требований      

```
regula scan -f <file-path>
```

### Сканирование удаленного хранилища на предмет нарушений нормативных требований     

```
regula scan -r <repository-url>
```

### Сканирование файла плана Terraform на предмет нарушений требований        

```
regula scan -p <plan-file>
```

### Сканирование каталога и вывод результатов в формате JSON      

```
regula scan -d <directory-path> --output json
```

### Проверка политик неограниченных ведер S3:
   

```
name: S3 bucket policy should not be unrestricted
resource_type: aws_s3_bucket_policy
violating_actions:
  - "*"
```

### Убедитесь, что группы безопасности не разрешают неограниченный входящий трафик:


```
name: Security groups should not allow unrestricted ingress traffic
resource_type: aws_security_group_rule
violating_actions:
  - ingress
violating_fields:
  - source_security_group_id: "sg-00000000"
  - cidr_blocks:
      - "0.0.0.0/0"
```

### Enforce encryption for EBS volumes:
  

```
name: EBS volumes should be encrypted
resource_type: aws_ebs_volume
violating_actions:
  - create
  - modify
violating_fields:
  - encrypted: false
```

### Проверьте наличие общедоступных экземпляров EC2:
   

```
name: EC2 instances should not be publicly accessible
resource_type: aws_instance
violating_fields:
  - public_ip_address: "*"
```

### Убедитесь, что политики IAM не имеют подстановочных разрешений на ресурсы:
    

```
name: IAM policies should not have wildcard resource permissions
resource_type: aws_iam_policy
violating_fields:
  - resources:
      - "*"
```





## eBPF (расширенный пакетный фильтр Беркли)


### Проверьте установку Cilium     

```
kubectl get pods -n kube-system
```



### Просмотр журналов регистрации агентов Cilium    

```
kubectl logs -n kube-system -l k8s-app=cilium
```




### Просмотр журнала регистрации операторов Cilium   

```
kubectl logs -n kube-system -l name=cilium-operator
```




### Опишите NetworkPolicy  

```
kubectl describe networkpolicy <name>
```




### Применить политику L7 (уровень 7)   

```
kubectl apply -f <l7policy.yaml>
```




### Список политик L7     

```
kubectl get l7policy
```




### Обновите Cilium      

```
helm upgrade cilium cilium/cilium --version <version>
```




### Обеспечение соблюдения сетевых политик:

 

```
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: web-policy
spec:
  endpointSelector:
    matchLabels:
      app: web
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: db
  egress:
    - toEndpoints:
        - matchLabels:
            app: internet
```




###  Включить шифрование для связи с Cilium:

```
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: encryption-policy
spec:
  endpointSelector:
    matchLabels:
      app: cilium
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: cilium
  egress:
    - toEndpoints:
        - matchLabels:
            app: cilium
  egressEncryption:
    - identity:
        identityName: cilium
        identityIssuer: self
        identityPrivateKey: <base64-encoded-private-key>
```




### Внедрение политики DNS

```
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: dns-policy
spec:
  endpointSelector:
    matchLabels:
      app: dns-server
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: web
  dns:
    allowNonCiliumDNSResponse: false
```




### Включить проверку HTTP     

```
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: http-inspection
spec:
  endpointSelector:
    matchLabels:
      app: web
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: internet
  http:
    - match:
        - method: GET
          path: /api/secret
      inspectResponse: true
```



### Внедрение профилей безопасности     

```
apiVersion: cilium.io/v2
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: security-profile
spec:
  endpointSelector:
    matchLabels:
      app: cilium
  securityProfile:
    capabilities:
      - NET_ADMIN
      - SYS_MODULE
    fileAccess:
      - path: /etc/shadow
        access: rw
```






















