---
layout: default
title: Monitoring
parent: Operate
---

# Мониторинг
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---

Мониторинг в DevSecOps - это практика постоянного наблюдения и анализа ИТ-систем, приложений и инфраструктуры организации с целью выявления потенциальных проблем безопасности, обнаружения и реагирования на инциденты безопасности, а также обеспечения соответствия политикам и нормам безопасности.

В DevSecOps мониторинг является важнейшим компонентом комплексной стратегии безопасности, позволяющим организациям быстро и эффективно выявлять угрозы безопасности и реагировать на них. К числу ключевых преимуществ мониторинга в DevSecOps относятся:

1. Раннее обнаружение инцидентов безопасности: Благодаря постоянному мониторингу систем и приложений организации могут обнаруживать инциденты безопасности на ранних стадиях и принимать незамедлительные меры по их устранению.

2. Улучшенное реагирование на инциденты: Благодаря мониторингу и анализу в режиме реального времени организации могут быстро и эффективно реагировать на инциденты безопасности, сводя к минимуму последствия потенциального взлома.

3. Повышение соответствия нормативным требованиям: Благодаря мониторингу систем и приложений на предмет соответствия политикам и нормам безопасности организации могут убедиться в том, что они выполняют свои обязательства по обеспечению безопасности.

4. Улучшение видимости: Мониторинг позволяет организациям получить более полную информацию о своих ИТ-системах и приложениях, что дает им возможность выявлять потенциальные риски безопасности и принимать упреждающие меры по их устранению.

Существует множество инструментов и технологий мониторинга, которые можно использовать в DevSecOps, включая средства анализа журналов, инструменты сетевого мониторинга и решения для управления информацией и событиями безопасности (SIEM). Эти инструменты могут быть интегрированы с другими практиками DevSecOps, такими как непрерывная интеграция и непрерывное развертывание, для обеспечения безопасности в жизненном цикле разработки приложений.




## Prometheus

Запустите сервер Prometheus:

```
$ ./prometheus --config.file=prometheus.yml
```

Проверьте состояние сервера Prometheus:


```
$ curl http://localhost:9090/-/healthy
```

Запрашивайте данные с помощью PromQL:


```
http://localhost:9090/graph?g0.range_input=1h&g0.expr=up&g0.tab=0
```

## Grafana

Добавьте источник данных Prometheus:


```
http://localhost:3000/datasources/new?gettingstarted
```


## Nagios

Настройте сервер Nagios:


```
/etc/nagios3/conf.d/
```

Проверьте конфигурацию сервера Nagios:


```
$ sudo /usr/sbin/nagios3 -v /etc/nagios3/nagios.cfg
```

## Zabbix

Настройте агент Zabbix на сервере: Отредактируйте файл конфигурации агента Zabbix /etc/zabbix/zabbix_agentd.conf, чтобы указать IP-адрес и имя хоста сервера Zabbix, а также включить мониторинг системных ресурсов, таких как процессор, память, использование диска и сетевой интерфейс. Пример конфигурации:

```
Server=192.168.1.100
ServerActive=192.168.1.100
Hostname=web-server
EnableRemoteCommands=1
UnsafeUserParameters=1
# Мониторинг системных ресурсов
UserParameter=cpu.usage[*],/usr/bin/mpstat 1 1 | awk '/Average:/ {print 100-$NF}'
UserParameter=memory.usage,free | awk '/Mem:/ {print $3/$2 * 100.0}'
UserParameter=disk.usage[*],df -h | awk '$1 == $1 {print int($5)}'
UserParameter=network.in[*],cat /proc/net/dev | grep $1 | awk '{print $2}'
UserParameter=network.out[*],cat /proc/net/dev | grep $1 | awk '{print $10}'
```

Настройте сервер Zabbix: Войдите в веб-интерфейс Zabbix и перейдите на вкладку "Конфигурация". Создайте новый хост с тем же именем, что и у сервера, за которым ведется наблюдение, и укажите IP-адрес и порт агента Zabbix. Добавьте на хост элементы для мониторинга системных ресурсов, указанных в файле конфигурации агента Zabbix. Примеры элементов:

* Использование процессора: `system.cpu.util[,idle]`.
* Использование памяти: `vm.memory.size[available]`.
* Использование диска: `vfs.fs.size[/,pfree]`
* Входящий сетевой трафик: `net.if.in[eth0]`
* Исходящий сетевой трафик: `net.if.out[eth0]`

Настройка триггеров: Настройте триггеры для оповещения о превышении определенного порога любым контролируемым элементом. Например, установите триггер на элемент "Использование процессора", который будет оповещать, когда его использование превысит 80 %.

Настройте действия: Создайте действия для уведомления соответствующих заинтересованных сторон при срабатывании триггера. Например, отправьте электронное письмо команде веб-приложений и системным администраторам.


## Datadog

Отредактируйте файл конфигурации агента Datadog `/etc/datadog-agent/datadog.yaml` и добавьте следующие строки:

```
# Сбор показателей процессора
procfs_path: /proc
cpu_acct: true

# Сбор данных о памяти
meminfo_path: /proc/meminfo
```

Чтобы просмотреть метрики процессора и памяти, перейдите в Datadog Metrics Explorer и найдите метрики `system.cpu.usage` и `system.mem.used`.



Вот несколько примеров команд, которые можно использовать для сбора метрик процессора и памяти с помощью Datadog:

Для сбора метрик процессора:


```
curl -X POST -H "Content-type: application/json" -d '{
    "series": [
        {
            "metric": "system.cpu.usage",
            "points": [
                [
                    '"$(date +%s)"',
                    "$(top -bn1 | grep '%Cpu(s)' | awk '{print $2 + $4}')"
                ]
            ],
            "host": "my-host.example.com",
            "tags": ["environment:production"]
        }
    ]
}' "https://api.datadoghq.com/api/v1/series?api_key=<YOUR_API_KEY>"
```


Чтобы собрать метрики памяти:


```
curl -X POST -H "Content-type: application/json" -d '{
    "series": [
        {
            "metric": "system.mem.used",
            "points": [
                [
                    '"$(date +%s)"',
                    "$(free -m | awk '/Mem:/ {print $3}')"
                ]
            ],
            "host": "my-host.example.com",
            "tags": ["environment:production"]
        }
    ]
}' "https://api.datadoghq.com/api/v1/series?api_key=<YOUR_API_KEY>"
```

Обратите внимание, что эти команды предполагают, что в вашей системе установлены необходимые инструменты (`top`, `free`) для сбора метрик процессора и памяти. Вы можете настроить поля `metric`, `host` и `tags` в соответствии с вашими настройками.




## New Relic

Чтобы установить агент New Relic Infrastructure на сервер Ubuntu, выполните следующие действия:


```
curl -Ls https://download.newrelic.com/infrastructure_agent/linux/apt | sudo bash
sudo apt-get install newrelic-infra
sudo systemctl start newrelic-infra
```

Чтобы установить агент New Relic Infrastructure на сервер CentOS/RHEL, выполните следующие действия:


```
curl -Ls https://download.newrelic.com/infrastructure_agent/linux/yum/el/7/x86_64/newrelic-infra.repo | sudo tee /etc/yum.repos.d/newrelic-infra.repo
sudo yum -y install newrelic-infra
sudo systemctl start newrelic-infra
```

Чтобы просмотреть показатели процессора и памяти для конкретного сервера с помощью New Relic API:

```
curl -X GET 'https://api.newrelic.com/v2/servers/{SERVER_ID}/metrics/data.json' \
     -H 'X-Api-Key:{API_KEY}' \
     -i \
     -d 'names[]=System/CPU/Utilization&values[]=average_percentage' \
     -d 'names[]=System/Memory/Used/Bytes&values[]=average_value' \
     -d 'from=2022-05-01T00:00:00+00:00&to=2022-05-10T00:00:00+00:00'
```




## AWS CloudWatch


1- Чтобы установить агент CloudWatch в Linux, можно воспользоваться следующими командами:

```
curl https://s3.amazonaws.com/amazoncloudwatch-agent/amazon_linux/amd64/latest/amazon-cloudwatch-agent.rpm -O
sudo rpm -i amazon-cloudwatch-agent.rpm
```

2- Настройка агента CloudWatch для сбора метрик


В Linux вы можете создать файл конфигурации по адресу `/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json` со следующим содержимым:


```
{
    "metrics": {
        "namespace": "CWAgent",
        "metricInterval": 60,
        "append_dimensions": {
            "InstanceId": "${aws:InstanceId}"
        },
        "metrics_collected": {
            "cpu": {
                "measurement": [
                    "cpu_usage_idle",
                    "cpu_usage_iowait",
                    "cpu_usage_user",
                    "cpu_usage_system"
                ],
                "metrics_collection_interval": 60,
                "totalcpu": false
            },
            "memory": {
                "measurement": [
                    "mem_used_percent"
                ],
                "metrics_collection_interval": 60
            }
        }
    }
}
```


В Windows вы можете использовать мастер настройки агента CloudWatch Agent Configuration Wizard для создания файла конфигурации со следующими параметрами:


```
- Choose "AWS::EC2::Instance" as the resource type to monitor
- Choose "Performance counters" as the log type
- Select the following counters to monitor:
  - Processor Information -> % Processor Time
  - Memory -> % Committed Bytes In Use
- Set the metric granularity to 1 minute
- Choose "CWAgent" as the metric namespace
- Choose "InstanceId" as the metric dimension
```

3- Запуск агента CloudWatch
После настройки агента CloudWatch его можно запустить на экземпляре EC2 с помощью следующих команд:

```
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json
sudo service amazon-cloudwatch-agent start
```

4- Просмотр метрик в CloudWatch

Через несколько минут агент CloudWatch начнет собирать метрики процессора и памяти с экземпляра EC2. Вы можете просмотреть эти показатели в консоли CloudWatch, выполнив следующие действия:

* Перейдите в консоль CloudWatch и выберите "Метрики" в меню слева.
* В разделе "Пространства имен AWS" выберите "CWAgent".
* Вы увидите список метрик для экземпляра EC2, который вы отслеживаете, включая использование процессора и памяти. Вы можете выбрать отдельные метрики, чтобы просмотреть графики и настроить оповещения на основе этих метрик.


## Монитор Azure


1- Настройте агент на сбор метрик процессора и памяти, добавив следующие параметры в файл конфигурации агента:


```
    {
      "metrics": {
        "performance": {
          "collectionFrequencyInSeconds": 60,
          "metrics": [
            {
              "name": "\\Processor(_Total)\\% Processor Time",
              "category": "Processor",
              "counter": "% Processor Time",
              "instance": "_Total"
            },
            {
              "name": "\\Memory\\Available Bytes",
              "category": "Memory",
              "counter": "Available Bytes",
              "instance": null
            }
          ]
        }
      }
    }
```

2- Перезапустите агент Azure Monitor, чтобы применить новую конфигурацию.

3- Выберите виртуальную машину или сервер, для которых вы хотите просмотреть показатели.
4- Выберите метрики процессора и памяти, которые вы хотите просмотреть.
5 - Настройте предупреждения или уведомления, которые вы хотите получать на основе этих показателей.

Для сбора показателей процессора и памяти с помощью Azure Monitor можно также использовать Azure Monitor REST API или Azure CLI. Вот пример команды Azure CLI для сбора показателей процессора и памяти:



```
az monitor metrics list --resource {resource_id} --metric-names "\Processor(_Total)\% Processor Time" "Memory\Available Bytes" --interval PT1M --start-time 2022-05-20T00:00:00Z --end-time 2022-05-21T00:00:00Z
```

Эта команда извлекает метрики процессора и памяти для определенного ресурса (идентифицированного по `{resource_id}`) за однодневный период (с 20 мая 2022 года по 21 мая 2022 года) с интервалом в одну минуту. При необходимости вы можете изменить параметры, чтобы получить другие показатели или временные диапазоны.




## Мониторинг облака Google

1- Установите агент Stackdriver на экземпляр GCE. Это можно сделать с помощью следующей команды:

```
curl -sSO https://dl.google.com/cloudagents/install-monitoring-agent.sh
sudo bash install-monitoring-agent.sh
```

2- Убедитесь, что агент мониторинга запущен, проверив состояние его службы:


```
sudo service stackdriver-agent status
```

3- В Google Cloud Console перейдите в раздел Monitoring > Metrics Explorer и выберите метрику `CPU usage` в типе ресурса `Compute Engine VM Instance`. Установите агрегацию на `среднее`, выберите созданный вами экземпляр GCE и нажмите кнопку `Создать`, чтобы просмотреть метрику использования процессора для вашего экземпляра.


4- Чтобы собрать показатели памяти, повторите шаг 5, но вместо `CPU usage` выберите метрику `Memory usage`.


## Netdata

* В веб-интерфейсе Netdata перейдите в раздел "Dashboard" и выберите график "system.cpu", чтобы просмотреть показатели использования процессора. Также можно выбрать график "system.ram" для просмотра показателей использования памяти.

* Чтобы уменьшить количество отказов с помощью машинного обучения, вы можете настроить функцию обнаружения аномалий Netdata. В веб-интерфейсе Netdata перейдите в раздел "Обнаружение аномалий" и выберите "Добавить тревогу".

* В поле "Обнаружить" выберите "cpu.system". Это позволит обнаружить аномалии в использовании системного процессора.

* Для поля "Серьезность" выберите "Предупреждение". При обнаружении аномалии будет выдаваться предупреждение.

* Для поля "Действие" выберите "Уведомлять". При обнаружении аномалии будет отправлено уведомление.

* Вы также можете настроить функцию предиктивной аналитики Netdata, чтобы предсказать, когда система выйдет из строя. В веб-интерфейсе Netdata перейдите в раздел "Прогнозирование" и выберите "Добавить алгоритм".

* В поле "Алгоритм" выберите "Авторегрессия". Это позволит использовать авторегрессию для прогнозирования поведения системы.

* Для поля "Цель" выберите "cpu.system". Это позволит предсказать использование процессора.

* Для поля "Окно" выберите "30 минут". Для прогнозирования будет использоваться 30-минутное окно.

* Наконец, нажмите кнопку "Создать", чтобы создать алгоритм.


## Sysdig


- [ ] Перехватывайте системные события и записывайте их в файл.

```
sysdig -w <filename.scap>
```

- [ ] Настройка формата вывода захваченных событий

```
sysdig -p "%evt.num %evt.type %evt.args"
```

- [ ] Фильтруйте события по имени процесса (например, nginx).

```
sysdig proc.name=nginx
```

- [ ] Считывание событий из файла и фильтрация по имени процесса (например, httpd).

```
sysdig -r <filename.scap> proc.name=httpd
```


- [ ] Отображение событий открытия файлов

```
sysdig -c file_open
```

- [ ] Настройка формата вывода захваченных событий

```
sysdig -c fdbytes_by fd.sport
```


- [ ] Мониторинг IP-трафика в режиме реального времени.

```
sysdig -c spy_ip
```

- [ ] Показывает верхние контейнеры по использованию процессора.

```
sysdig -c topcontainers_cpu
```

- [ ] Отображение времени выполнения процесса.

```
sysdig -c proc_exec_time
```

- [ ] Отслеживайте системные вызовы, выполняемые процессами.

```
sysdig -c proc_calls
```

- [ ] Верхний контейнер

```
sysdig -c container_top
```

- [ ] Настройка формата вывода захваченных событий

```
Показывает верхние контейнеры по использованию ресурсов.
```

- [ ] Отображение информации о подах Kubernetes.

```
sysdig -c k8s.pods
```

- [ ] Отслеживайте события развертывания Kubernetes.

```
sysdig -c k8s.deployments
```


## Dynatrace



- [ ] Получение данных о среднем использовании процессора за определенный промежуток времени.
Создание пользовательского профиля оповещения:

```
timeseriesquery "metric=CPU|avg:system.cpu.usage" --start-time="2023-05-01T00:00:00Z" --end-time="2023-05-02T00:00:00Z": 
```

- [ ] Создайте новый профиль оповещения для обнаружения высокого использования памяти с пороговым значением 80%.
Получение событий развертывания

```
create-alerting-profile --name="High Memory Usage" --metric="memory.resident" --condition="> threshold:80" --enabled=true: 
```

- [ ] Получение списка событий развертывания, произошедших в определенном диапазоне времени.

```
deployment-events --start-time="2023-05-01T00:00:00Z" --end-time="2023-05-02T00:00:00Z"
```

- [ ] Создайте новую пользовательскую приборную панель с макетом 2x2.

```
dashboard create --name="My Custom Dashboard" --layout="2x2": 
```

- [ ] Проанализируйте производительность и зависимости конкретного приложения под названием "My Application".

```
application analyze --name="My Application": 
```




## Alerta

### Отправить новое оповещение

Создайте и отправьте новое оповещение в систему Alerta

```
curl -X POST -H "Content-Type: application/json" -d '{
  "resource": "webserver1",
  "event": "High CPU Usage",
  "environment": "Production",
  "severity": "major",
  "service": ["Web Servers"],
  "text": "High CPU usage detected on webserver1"
}' https://your-alerta-url/api/alert
```



### Запрос оповещений

Получение оповещений по определенным критериям


```
curl -X GET "https://your-alerta-url/api/alert?status=open&severity=major"
```




### Обновить оповещение

Обновление сведений или статуса существующего оповещения


```
curl -X PUT -H "Content-Type: application/json" -d '{
  "status": "ack",
  "note": "Investigating the issue..."
}' https://your-alerta-url/api/alert/<alert_id>
```



### Удаление оповещения

Удалите существующее оповещение из системы Alerta

```
curl -X DELETE https://your-alerta-url/api/alert/<alert_id>
```



### Получить историю оповещений

Получение истории изменений для конкретного оповещения.


```
curl -X GET https://your-alerta-url/api/alert/<alert_id>/history
```



## ChatOps

### Element

#### Создание новой учетной записи Matrix

```
# Riot
riot-web

# Element
element-web
```

#### Вступление в чат Matrix

```
# Riot
riot-web --url "https://matrix.org" --room "room_id"

# Element
element-web --url "https://matrix.org" --room "room_id"
```

#### Отправка сообщения в чате Matrix

```
# Riot
riot-web --url "https://matrix.org" --room "room_id" --message "Hello, World!"

# Element
element-web --url "https://matrix.org" --room "room_id" --message "Hello, World!"
```

#### Отображение сведений о комнате в Matrix

```
# Riot
riot-web --url "https://matrix.org" --room "room_id" --details

# Element
element-web --url "https://matrix.org" --room "room_id" --details
```

#### Создание нового пользователя матрицы

```
# Riot
riot-web --url "https://matrix.org" --register --username "new_user" --password "password"

# Element
element-web --url "https://matrix.org" --register --username "new_user" --password "password"
```

#### Отправка уведомления о развертывании в чат

```
# Riot
riot-web --url "https://matrix.org" --room "room_id" --message "Deployment successful!"

# Element
element-web --url "https://matrix.org" --room "room_id" --message "Deployment successful!"
```


#### Запуск пайплайна CI/CD из чата

```
# Riot
riot-web --url "https://matrix.org" --room "room_id" --message "!pipeline deploy"

# Element
element-web --url "https://matrix.org" --room "room_id" --message "!pipeline deploy"
```

#### Выполнение команды на удаленном сервере из чата

```
# Riot
riot-web --url "https://matrix.org" --room "room_id" --message "!exec ssh user@server 'ls -l'"

# Element
element-web --url "https://matrix.org" --room "room_id" --message "!exec ssh user@server 'ls -l'"
```


### Slack

#### Отправьте уведомление о развертывании на канал Slack:

```
slackcli --channel "#channel_name" --message "Deployment successful!"
```

#### Запуск пайплайна CI/CD из канала Slack:

```
slackcli --channel "#channel_name" --message "!pipeline deploy"
```

#### Выполните команду на удаленном сервере из канала Slack:

```
slackcli --channel "#channel_name" --message "!exec ssh user@server 'ls -l'"
```

#### Запросите обновление статуса у внешнего сервиса в канале Slack:

```
slackcli --channel "#channel_name" --message "!status check"
```

#### Создайте новый тикет в системе тикетов из канала Slack:

```
slackcli --channel "#channel_name" --message "!ticket create 'New issue: Need assistance'"
```




## Robusta

Чтобы задать пользовательские допуски или nodeSelector, обновите файл generated_values.yaml следующим образом:


```
global_config:
  krr_job_spec:
    tolerations:
    - key: "key1"
      operator: "Exists"
      effect: "NoSchedule"
    nodeSelector:
      nodeName: "your-selector
```



## Sensu


### Зарегистрируйте новый чек в Sensu:


```
sensuctl check create mycheck --command "check_mycheck.sh" --subscriptions linux --handlers default
```


### Зарегистрируйте новый чек в Sensu:


```
sensuctl check create mycheck --command "check_mycheck.sh" --subscriptions linux --handlers default
```


### Создайте новый обработчик в Sensu:



```
sensuctl handler create myhandler --type pipe --command "myhandler.sh"
```


### Создайте новый актив в Sensu:



```
sensuctl asset create myasset --url https://example.com/myasset.tar.gz --sha512sum abcdef1234567890
```


### Создайте новое пространство имен в Sensu:



```
sensuctl namespace create mynamespace
```




### Создайте новый фильтр в Sensu:



```
sensuctl filter create myfilter --action allow --expressions "event.Entity.Environment == 'production'"
```




## Steampipe


### Проверка наличия открытых групп безопасности в AWS

```
select
    aws_vpc.vpc_id,
    aws_security_group.group_id,
    aws_security_group.group_name,
    aws_security_group.description
from
    aws_security_group
    inner join aws_vpc on aws_security_group.vpc_id = aws_vpc.vpc_id
where
    aws_security_group.security_group_status = 'active'
    and aws_security_group.group_name != 'default'
    and aws_security_group.ip_permissions_egress = '0.0.0.0/0'
```


### Проверка наличия публичных ведер S3 в AWS

```
select
    aws_s3_bucket.bucket_name,
    aws_s3_bucket.creation_date,
    aws_s3_bucket.owner_id,
    aws_s3_bucket.owner_display_name
from
    aws_s3_bucket
where
    aws_s3_bucket.acl = 'public-read' or aws_s3_bucket.acl = 'public-read-write'
```


### Проверка наличия незашифрованных экземпляров RDS в AWS

```
select
    aws_rds_db_instance.db_instance_identifier,
    aws_rds_db_instance.encrypted,
    aws_rds_db_instance.engine,
    aws_rds_db_instance.engine_version
from
    aws_rds_db_instance
where
    aws_rds_db_instance.encrypted = false
```


### Проверьте наличие устаревших образов Docker в Docker Hub

```
select
    docker_hub_image.namespace,
    docker_hub_image.name,
    docker_hub_image.tag,
    docker_hub_image.image_created
from
    docker_hub_image
where
    docker_hub_image.image_created < date_sub(current_date, interval 30 day)
```




### Проверка наличия неиспользуемых ключей доступа IAM в AWS

```
select
    aws_iam_access_key.access_key_id,
    aws_iam_access_key.user_name,
    aws_iam_access_key.create_date,
    aws_iam_access_key.status
from
    aws_iam_access_key
where
    aws_iam_access_key.status = 'Active'
    and not exists (
        select
            1
        from
            aws_iam_user
        where
            aws_iam_user.user_name = aws_iam_access_key.user_name
            and aws_iam_user.user_enabled = true
    )
```




## Sysdig



### Фиксируйте активность системы и сохраняйте ее в файл для последующего анализа  

```
sysdig -w <output_file>
```


### Отображение сводки активности системы в реальном времени с указанием основных процессов 

```
sysdig -c top
```

### Отслеживайте сетевую активность с помощью сводки сетевых подключений  

```
sysdig -c netstat
```

### Фильтруйте активность системы по имени процесса  

```
sysdig proc.name=<process_name>
```

### Фильтруйте активность системы на основе идентификатора процесса (PID)  

```
sysdig proc.pid=<process_id>
```

### Отслеживайте активность дискового ввода-вывода для определенного процесса  

```
sysdig -p"%proc.name %evt.type" fd.type=char fd.name=/dev/sdX
```

### Отслеживание системных вызовов, выполняемых определенным процессом

```
sysdig -p"%proc.name %evt.type %evt.args" proc.name=<process_name>
```

### Мониторинг активности файловой системы в каталоге

```
sysdig -p"%evt.type %evt.args" evt.dir=<directory_path>
```

### Мониторинг системных вызовов, связанных с созданием процессов

```
sysdig -p"%proc.name %evt.type" evt.type=clone or evt.type=fork
```


## Sysdig Inspect


### Запустите Sysdig Inspect на работающем контейнере 

```
sysdig -p"%proc.name %evt.type" evt.type=clone or evt.type=fork
```

### Запуск Sysdig Inspect на определенном файле трассировки для автономного анализа 

```
sysdig-inspect trace <trace_file>
```

### Фильтруйте отображаемые события на основе определенного процесса 

```
filter proc.name=<process_name>
```

### Фильтруйте отображаемые события на основе определенного системного вызова 

```
filter evt.type=<system_call>
```

### Проверьте события файловой системы в определенном каталоге  

```
fs.directory=<directory_path>
```

### Проверьте системные вызовы, выполняемые процессом  

```
syscall <process_name>
```

### Проверьте сетевые подключения процесса  

```
netconn <process_name>
```

### Проверка открытых файловых дескрипторов процесса  

```
openfiles <process_name>
```

### Отображение сводки перехваченных системных вызовов и событий 

```
events
```


## Мониторинг файлов cron  


https://github.com/sqall01/LSMS/blob/main/scripts/monitor_cron.py



## Мониторинг файла /etc/hosts 


https://github.com/sqall01/LSMS/blob/main/scripts/monitor_hosts_file.py


## Мониторинг файла /etc/ld.so.preload 


https://github.com/sqall01/LSMS/blob/main/scripts/monitor_ld_preload.py


## Мониторинг файла /etc/passwd  


https://github.com/sqall01/LSMS/blob/main/scripts/monitor_passwd.py


## Модули мониторинга 


https://github.com/sqall01/LSMS/blob/main/scripts/monitor_modules.py


## Мониторинг файлов authorized_keys SSH 


https://github.com/sqall01/LSMS/blob/main/scripts/monitor_ssh_authorized_keys.py


## Мониторинг файлов модулей systemd  


https://github.com/sqall01/LSMS/blob/main/scripts/monitor_systemd_units.py


## Поиск исполняемых файлов в /dev/shm 


https://github.com/sqall01/LSMS/blob/main/scripts/search_dev_shm.py


## Поиск программ без файлов (memfd_create)    


https://github.com/sqall01/LSMS/blob/main/scripts/search_memfd_create.py


## Поиск скрытых файлов ELF  


https://github.com/sqall01/LSMS/blob/main/scripts/search_hidden_exe.py



## Поиск в неизменяемых файлах  


https://github.com/sqall01/LSMS/blob/main/scripts/search_immutable_files.py




## Поиск подражаний потоков ядра  


https://github.com/sqall01/LSMS/blob/main/scripts/search_non_kthreads.py



## Поиск процессов, которые были запущены в отключенном сеансе SSH  


https://github.com/sqall01/LSMS/blob/main/scripts/search_ssh_leftover_processes.py




## Поиск запущенных удаленных программ   


https://github.com/sqall01/LSMS/blob/main/scripts/search_deleted_exe.py



## Тестовый скрипт для проверки работы оповещений   


https://github.com/sqall01/LSMS/blob/main/scripts/test_alert.py



## Проверка целостности установленных пакетов .deb   


https://github.com/sqall01/LSMS/blob/main/scripts/verify_deb_packages.py

