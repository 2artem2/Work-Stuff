---
layout: default
title:  Secure Pipeline
parent: Code
---

# Безопасный пайплайн
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---



Безопасный пайплай - это набор процессов и инструментов, используемых для создания, тестирования и развертывания программного обеспечения таким образом, чтобы безопасность была приоритетной на всех этапах жизненного цикла разработки. Цель безопасного пайплай - обеспечить тщательную проверку приложений на уязвимости и соответствие стандартам безопасности перед выпуском в производство.


Безопасный пайплай обычно включает в себя следующие этапы:

1. Управление исходным кодом: Разработчики используют инструменты управления исходным кодом, такие как Git или SVN, для управления кодом приложения.

2. Сборка: Код приложения собирается в исполняемый код с помощью инструмента сборки, такого как Maven или Gradle.

3. Статический анализ: Инструмент статического анализа, например SAST, используется для проверки кода на наличие уязвимостей.

4. Юнит-тестирование: Разработчики пишут модульные тесты, чтобы убедиться, что приложение функционирует так, как ожидается, и выявить любые ошибки и недочеты.

5. Динамический анализ: Инструмент динамического анализа, например DAST, используется для тестирования приложения в работающей среде и выявления уязвимостей в системе безопасности.

6. Репозиторий артефактов: Приложение и все его зависимости хранятся в репозитории артефактов, например JFrog или Nexus.

7. Среда постановки: Приложение развертывается в среде постановки для дальнейшего тестирования и проверки.

8. Проверка соответствия: Инструмент проверки соответствия используется для проверки соответствия приложения всем нормативным требованиям или требованиям к соответствию.

9. Утверждение: Приложение проверяется и утверждается для развертывания в производстве.

10. Развертывание: Приложение развертывается в производство с помощью инструмента развертывания, например Ansible или Kubernetes.

Внедряя безопасный пайплай, организации могут гарантировать, что их приложения тщательно проверяются на уязвимости и соответствие стандартам безопасности, что снижает риск нарушения безопасности и обеспечивает повышенную устойчивость приложений к атакам.






Шаг 1: Настройте контроль версий

* Используйте систему контроля версий (СКВ), например Git, для управления кодом вашего приложения.
* Храните код в частном репозитории и ограничьте доступ к нему для авторизованных пользователей.
* Используйте строгие средства аутентификации и авторизации для защиты доступа к репозиторию.

Шаг 2: Внедрите непрерывную интеграцию

* Используйте инструмент непрерывной интеграции (CI), например Jenkins или Travis CI, чтобы автоматизировать процесс сборки.
* Убедитесь, что инструмент CI работает в безопасной среде.
* Используйте контейнеризацию для изоляции среды сборки и предотвращения конфликтов зависимостей друг с другом.

Шаг 3: Выполните автоматизированное тестирование безопасности

* Используйте инструменты SAST, DAST и SCA для автоматизированного тестирования безопасности кода приложений.
* Интегрируйте эти инструменты в пайплай CI, чтобы тестирование безопасности выполнялось автоматически при каждой сборке.
* Настройте инструменты так, чтобы они сообщали о любых проблемах безопасности и не выполняли сборку в случае обнаружения критических уязвимостей.

Шаг 4: Внедрите непрерывное развертывание

* Используйте инструмент непрерывного развертывания (CD), например Kubernetes или AWS CodeDeploy, чтобы автоматизировать процесс развертывания.
* Внедрите процесс выпуска, включающий тщательное тестирование и проверку, чтобы гарантировать, что развертывается только безопасный и стабильный код.

Шаг 5: Мониторинг и реагирование на угрозы безопасности

* Внедрите средства мониторинга безопасности для обнаружения угроз безопасности и реагирования на них в режиме реального времени.
* Используйте такие инструменты, как системы обнаружения вторжений (IDS) и системы управления информацией и событиями безопасности (SIEM), для мониторинга инфраструктуры и приложений.
* Внедрите план реагирования на инциденты безопасности для быстрого реагирования на обнаруженные инциденты безопасности.


пример безопасного пайплайна CI/CD


```
# Определите этапы пайплайна
stages:
  - build
  - test
  - security-test
  - deploy

# Определите задания для каждого этапа
jobs:
  build:
    # Соберите образ Docker и пометьте его фиксацией SHA
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v2
      - name: Build Docker image
        run: |
          docker build -t myapp:${{ github.sha }} .
          docker tag myapp:${{ github.sha }} myapp:latest

  test:
    # Выполняйте модульные и интеграционные тесты
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v2
      - name: Install dependencies
        run: npm install
      - name: Run tests
        run: npm test

  security-test:
    # Выполнение автоматизированного тестирования безопасности с использованием инструментов SAST, DAST и SCA.
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v2
      - name: Perform SAST
        uses: shiftleftio/action-sast@v3.3.1
        with:
          scan-targets: .
          shiftleft-org-id: ${{ secrets.SHIFTLEFT_ORG_ID }}
          shiftleft-api-key: ${{ secrets.SHIFTLEFT_API_KEY }}
      - name: Perform DAST
        uses: aquasecurity/trivy-action@v0.5.0
        with:
          image-ref: myapp:${{ github.sha }}
      - name: Perform SCA
        uses: snyk/actions@v1
        with:
          file: package.json
          args: --severity-threshold=high

  deploy:
    # Развертывание приложения в производственной среде
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/master'
    steps:
      - name: Deploy to production
        uses: appleboy/ssh-action@master
        with:
          host: production-server.example.com
          username: ${{ secrets.PRODUCTION_SERVER_USERNAME }}
          password: ${{ secrets.PRODUCTION_SERVER_PASSWORD }}
          script: |
            docker pull myapp:latest
            docker stop myapp || true
            docker rm myapp || true
            docker run -d --name myapp -p 80:80 myapp:latest
```



В этом примере файл YAML определяет пайплайн CI/CD с четырьмя этапами: сборка, тестирование, проверка безопасности и развертывание. На каждом этапе есть задание, выполняющее определенный набор задач. Задание `build` создает образ Docker для приложения, задание `test` запускает модульные и интеграционные тесты, задание `ecurity-test` выполняет автоматизированное тестирование безопасности с помощью инструментов SAST, DAST и SCA, а задание `deploy` развертывает приложение в производственной среде.

Каждое задание определяется параметром `runs-on`, который указывает операционную систему, на которой должно выполняться задание. Шаги для каждого задания определяются с помощью параметров `name` и `run`, которые указывают имя шага и команду для выполнения. Параметр `uses` используется для указания внешних действий или пакетов, которые должны быть использованы в шаге.

Параметр `if` используется для условного запуска задания на основе определенного условия, например ветки или тега, которые запустили пайплайн. Секреты хранятся в хранилище секретов репозитория GitHub, а доступ к ним осуществляется с помощью синтаксиса `${{ secrets.SECRET_NAME }}`.


## Buildkite

В файле конфигурации пайплайна (например, `.buildkite/pipeline.yml`) добавьте шаг для запуска инструмента сканирования уязвимостей.

```
steps:
  - label: "Security Scan"
    command: |
      # Запустите инструмент для сканирования уязвимостей.
      # Замените команду и параметры на соответствующие используемому инструменту
      my-vulnerability-scanner scan --output report.txt

      # Печать созданного отчета
      cat report.txt

    # Определите условия, при которых этот шаг должен выполняться (например, в определенных ветках или запросах на поставку).
    branches: master
```

## Travis

Откройте файл `.travis.yml` вашего проекта для редактирования.


```
script:
  - |
    # Запустите инструмент для сканирования уязвимостей.
    # Замените команду и параметры на соответствующие используемому инструменту
    my-vulnerability-scanner scan --output report.txt

    # Печать созданного отчета
    cat report.txt
```


## Drone

Откройте файл `.drone.yml` вашего проекта для редактирования.

```
pipeline:
  security:
    image: your-vulnerability-scanner-image
    commands:
      - |
        # Запустите инструмент для сканирования уязвимостей.
        # Замените команду и параметры на соответствующие используемому инструменту
        my-vulnerability-scanner scan --output report.txt

        # Print the generated report
        cat report.txt
```





## Tekton

### Пример потока

1 - Создайте Dockerfile:

```
FROM golang:1.16-alpine
WORKDIR /app
COPY . .
RUN go build -o myapp
CMD ["./myapp"]
```

2- Создайте задачу Tekton (build-task.yaml):

```
apiVersion: tekton.dev/v1beta1
kind: Task
metadata:
  name: build-task
spec:
  steps:
    - name: build
      image: golang:1.16-alpine
      workingDir: /workspace/source
      command:
        - go
      args:
        - build
        - -o
        - /workspace/myapp
        - .
      volumeMounts:
        - name: workspace
          mountPath: /workspace
    - name: package
      image: alpine
      command:
        - tar
      args:
        - czf
        - /workspace/myapp.tar.gz
        - -C
        - /workspace
        - myapp
      volumeMounts:
        - name: workspace
          mountPath: /workspace
    - name: publish
      image: ubuntu
      command:
        - echo
      args:
        - "Publishing artifact: /workspace/myapp.tar.gz"
      volumeMounts:
        - name: workspace
          mountPath: /workspace
  volumes:
    - name: workspace
      emptyDir: {}
```

3- Создайте пайплайн Tekton (pipeline.yaml):


```
apiVersion: tekton.dev/v1beta1
kind: Pipeline
metadata:
  name: myapp-pipeline
spec:
  tasks:
    - name: build-task
      taskRef:
        name: build-task
```

4- Примените задачу и пайплайн:

```
kubectl apply -f build-task.yaml
kubectl apply -f pipeline.yaml
```

5- Создание Tekton PipelineRun (pipelinerun.yaml):

```
apiVersion: tekton.dev/v1beta1
kind: PipelineRun
metadata:
  name: myapp-pipelinerun
spec:
  pipelineRef:
    name: myapp-pipeline
```

6- Применить PipelineRun:

```
kubectl apply -f pipelinerun.yaml
```



### Шпаргалка

1- Монтаж пайплайна Tekton  

```
kubectl apply --filename https://storage.googleapis.com/tekton-releases/pipeline/latest/release.yaml
```

2- Создать задачу 

```
kubectl apply --filename <task-definition.yaml>
```

3- Создать пайплайн 

```
kubectl apply --filename <pipeline-definition.yaml>
```

4- Создать PipelineRun  

```
kubectl apply --filename <pipelinerun-definition.yaml>
```

5- Список пайплайнов  

```
tkn pipeline list
```

6- Описание пайплайна

```
tkn pipeline describe <pipeline-name>
```

7- Список PipelineRuns 

```
tkn pipelinerun list
```

8- Описание PipelineRun  

```
tkn pipelinerun describe <pipelinerun-name>
```

9- Список задач  

```
tkn task list
```

10- Описание задачи 

```
tkn task describe <task-name>
```

11- Список TaskRuns 

```
tkn taskrun list
```

12- Описание a TaskRun  

```
tkn taskrun describe <taskrun-name>
```

13- Создание TriggerBinding 

```
kubectl apply --filename <triggerbinding-definition.yaml>
```

14- Создание TriggerTemplate  

```
kubectl apply --filename <triggertemplate-definition.yaml>
```

15- Создание a Trigger  

```
kubectl apply --filename <trigger-definition.yaml>
```

16- Список триггеров 

```
tkn trigger list
```

17- Описание тригера  

```
tkn trigger describe <trigger-name>
```

18- Удаление пайплайна

```
kubectl delete pipeline <pipeline-name>
```

19- Удаление PipelineRun  

```
kubectl delete pipelinerun <pipelinerun-name>
```

20- Удаление задачи 

```
kubectl delete task <task-name>
```






## Конфиденциальность как код


Установка инструмента Fides с помощью pip, менеджера пакетов Python

```
pip install fides
```

Проверяет указанную директорию на наличие проблем, связанных с конфиденциальностью, и конфиденциальных данных

```
fides scan <directory_path>
```


Создает подробный отчет о результатах сканирования и сохраняет его в указанном выходном файле

```
fides report -o <output_file>
```


Указание шаблона для исключения определенных файлов или каталогов из сканирования

```
fides scan --exclude <pattern>
```


Использует файл пользовательского набора правил для сканирования, позволяя определить конкретные правила конфиденциальности и проверки

```
fides scan --ruleset <ruleset_file>
```


Игнорирование определенных шаблонов или файлов, вызывающих ложные срабатывания во время сканирования.

```
fides scan --ignore <pattern>
```

Sets the output format for the generated report, such as JSON, CSV, or HTML

```
fides report --format <output_format>
```


Настройка завершения сканирования с ненулевым кодом при обнаружении проблем с конфиденциальностью, что обеспечивает интеграцию с пайплайном CI/CD.

```
fides scan --exit-code
```

## Безопасность непрерывного развертывания

### secureCodeBox

Установите secureCodeBox 

```
kubectl apply -f https://raw.githubusercontent.com/secureCodeBox/secureCodeBox/master/deploy/complete.yaml
```

2.  Выполните сканирование уязвимостей  

```
kubectl apply -f https://raw.githubusercontent.com/secureCodeBox/secureCodeBox/master/demo/scan-job.yaml
```

3.  Контролируйте ход сканирования 

```
kubectl get scan -w
```

4.  Просмотр результатов сканирования 

```
kubectl describe scan <scan-name>
```

5. Интегрируйте secureCodeBox с другими инструментами безопасности:

```
securecodebox-cli scan start --target <target-url> --scan-type <scan-type> --integration <integration-name>
или
Example: securecodebox-cli scan start --target https://example.com --scan-type zap-scan --integration jira
```

6. Планируйте регулярные сканирования с помощью Kubernetes CronJobs

```
kubectl apply -f https://raw.githubusercontent.com/secureCodeBox/secureCodeBox/master/demo/scheduled-scan.yaml
```

7. Интегрируйте secureCodeBox с вашим пайплайном CI/CD:

```
securecodebox-cli scan start --target <target-url> --scan-type <scan-type> --pipeline <pipeline-name>
или
Example: securecodebox-cli scan start --target https://example.com --scan-type nmap-scan --pipeline my-cicd-pipeline
```

8. Планируйте регулярные сканирования с помощью Kubernetes CronJobs

```
kubectl edit hook <hook-name>
```


### ThreatMapper

1. Установите ThreatMapper

```
git clone https://github.com/deepfence/ThreatMapper.git
cd ThreatMapper
./install.sh
```

2. Выполните оценку безопасности конкретной цели:

```
threat-mapper scan <target-ip>
```

3. Просмотрите результаты сканирования:

```
threat-mapper report <scan-id>
```

4. Интегрируйте ThreatMapper с вашим пайплайном CI/CD:

```
threat-mapper scan --target <target-ip> --pipeline <pipeline-name>
Example: threat-mapper scan --target 192.168.0.1 --pipeline my-cicd-pipeline
```

5. Настройте политики сканирования, изменив файлы конфигурации:

```
vim ~/.threat-mapper/config.yaml
```

6. Включите уведомления о результатах сканирования:

```
vim ~/.threat-mapper/config.yaml
```

7. Настройте нужные параметры уведомлений, например уведомления по электронной почте или оповещения в Slack.

```
crontab -e
```

Добавьте запись задания cron для выполнения команды сканирования threat-mapper через заданные промежутки времени.

8. Интеграция ThreatMapper с другими инструментами безопасности:

```
threat-mapper scan --target <target-ip> --integration <integration-name>
Example: threat-mapper scan --target 192.168.0.1 --integration jira
```

Мониторинг и устранение проблем безопасности по результатам сканирования:
Регулярно просматривайте отчеты о сканировании и принимайте необходимые меры для устранения выявленных проблем безопасности.

9. Создание визуализаций и отчетов

```
threat-mapper visualize <scan-id>
```

Эта команда создает визуализации результатов сканирования, такие как сетевые диаграммы и карты поверхности атаки.



## StackStorm



### Автоматизированное сканирование уязвимостей:

Описание: Планируйте регулярное сканирование уязвимостей с помощью таких инструментов сканирования, как Nessus или Qualys.

Команда/код: `st2 run vulnerability_scanner.scan`

Чтобы запланировать регулярное сканирование уязвимостей с помощью таких инструментов сканирования, как Nessus или Qualys, в StackStorm (st2), вы можете создать пользовательский пакет StackStorm и определить действие Python, вызывающее API инструмента сканирования уязвимостей. Вот пример фрагмента кода:

- [ ] Create a new StackStorm pack:

```
st2 pack create vulnerability_scanner
```

- [ ] Create a new Python action file scan.py within the pack:


```
# vulnerability_scanner/actions/scan.py

from st2common.runners.base_action import Action

class VulnerabilityScanAction(Action):
    def run(self):
        # Code to invoke the vulnerability scanning tool's API
        # Example: Nessus API call to start a scan
        # Replace <nessus_api_url>, <access_token>, and <scan_id> with your actual values
        response = requests.post(
            url="<nessus_api_url>/scans/<scan_id>/launch",
            headers={"X-ApiKeys": "<access_token>"},
        )
        if response.status_code == 200:
            return True
        else:
            return False
```

- [ ] Зарегистрируйте действие в файле pack.yaml:

```
# vulnerability_scanner/pack.yaml

actions:
  - vulnerability_scanner/actions/scan.py
```

Этот код представляет собой базовую структуру для вызова API инструмента сканирования уязвимостей. Вам нужно будет изменить его в соответствии с API и методом аутентификации вашего конкретного инструмента сканирования. 







### Оценка уязвимости:

Описание: Получение результатов сканирования уязвимостей и их анализ на предмет наличия критических уязвимостей.

Команда/код: `st2 run vulnerability_scanner.analyze_scan`

- [ ] Создайте новый пакет StackStorm:

```
st2 pack create vulnerability_assessment
```


- [ ] Создайте новый файл действия Python analyze.py внутри пакета:


```
# vulnerability_assessment/actions/analyze.py

from st2common.runners.base_action import Action
import requests

class VulnerabilityAssessmentAction(Action):
    def run(self):
        # Код для получения результатов сканирования уязвимостей из API инструмента сканирования
        # Пример: Вызов API Nessus для получения результатов сканирования
        # Замените <nessus_api_url>, <access_token> и <scan_id> на ваши фактические значения
        response = requests.get(
            url="<nessus_api_url>/scans/<scan_id>/results",
            headers={"X-ApiKeys": "<access_token>"},
        )

        if response.status_code == 200:
            results = response.json()
            # Выполните анализ результатов сканирования
            # Пример: Проверка на наличие критических уязвимостей
            critical_vulnerabilities = []
            for result in results:
                if result["severity"] == "Critical":
                    critical_vulnerabilities.append(result["name"])
            return critical_vulnerabilities
        else:
            return None
```



- [ ] Зарегистрируйте действие в файле pack.yaml:

```
# vulnerability_assessment/pack.yaml

actions:
  - vulnerability_assessment/actions/analyze.py
```

Этот код представляет собой базовую структуру для получения результатов сканирования уязвимостей из API инструмента сканирования и проведения анализа. Вам нужно будет изменить его в соответствии с API и методом аутентификации вашего конкретного инструмента сканирования. Кроме того, вы можете настроить логику анализа в соответствии с вашими специфическими требованиями.




### Триггер инцидента:

Описание: Обнаружение критической уязвимости и запуск рабочего процесса реагирования на инцидент.

Команда/код: `st2 run incident.trigger`


- [ ] Создайте новый пакет StackStorm:

```
st2 pack create incident_investigation
```




- [ ] Создайте новый файл действия Python gather_info.py внутри пакета:


```
# incident_investigation/actions/gather_info.py

from st2common.runners.base_action import Action
import requests

class IncidentInvestigationAction(Action):
    def run(self, vulnerability):
        # Код для сбора дополнительной информации об уязвимости
        # Пример: Запрос соответствующих журналов или систем
        # Замените <log_url> и <search_query> на ваши фактические значения
        response = requests.get(
            url=f"<log_url>/search?query={vulnerability}"
        )

        if response.status_code == 200:
            logs = response.json()
            # Проведите дальнейший анализ или извлеките необходимую информацию из журналов.
            # Пример: Вернуть записи журнала, связанные с уязвимостью
            return logs
        else:
            return None
```




- [ ] Зарегистрируйте действие в файле pack.yaml:


```
# incident_investigation/pack.yaml

actions:
  - incident_investigation/actions/gather_info.py
```



- [ ] Запустите действие по расследованию инцидента:


```
st2 run incident_investigation.gather_info vulnerability=<vulnerability_name>
```


Этот код представляет собой базовую структуру для сбора дополнительной информации об уязвимости путем запроса соответствующих журналов или систем. Вам нужно будет изменить его в соответствии с вашими конкретными источниками журналов или системами и синтаксисом запроса для получения необходимой информации.






### Расследование инцидента:

Описание: Соберите дополнительную информацию об уязвимости, запросив соответствующие журналы или системы.

Команда/код: `st2 run incident.investigate`


- [ ] Создайте новый пакет StackStorm:

```
st2 pack create incident_investigation
```



- [ ] Создайте новый файл интеграции investigate_vulnerability.yaml внутри пакета:


```
# incident_investigation/integrations/investigate_vulnerability.yaml

name: investigate_vulnerability
description: Gather additional information about a vulnerability by querying relevant logs or systems.

actions:
  - name: query_logs
    description: Query logs to gather information about the vulnerability
    enabled: true
    entry_point: query_logs.py
    runner_type: "python-script"
```




- [ ] Создайте новый файл сценария Python query_logs.py внутри пакета:


```
# incident_investigation/actions/query_logs.py

import requests
from st2common.runners.base_action import Action

class QueryLogsAction(Action):
    def run(self, vulnerability):
        # Код для запроса соответствующих журналов или систем
        # Замените <log_url> и <search_query> на ваши фактические значения
        response = requests.get(
            url=f"<log_url>/search?query={vulnerability}"
        )

        if response.status_code == 200:
            logs = response.json()
            # Проведите дальнейший анализ или извлеките необходимую информацию из журналов.
            # Пример: Вернуть записи журнала, связанные с уязвимостью
            return logs
        else:
            return None
```



- [ ] Зарегистрируйте интеграцию в файле pack.yaml:


```
# incident_investigation/pack.yaml

integrations:
  - integrations/investigate_vulnerability.yaml
```







### Уведомление и оповещение:

Описание: Отправка уведомлений команде реагирования на инцидент или заинтересованным сторонам через Slack, электронную почту или другие каналы связи.

Команда/код: `st2 run notification.send`



- [ ] Создайте новый пакет StackStorm:



```
st2 pack create notification_alerting
```




- [ ] Создайте новый файл интеграции send_notification.yaml внутри пакета:



```
# notification_alerting/integrations/send_notification.yaml

name: send_notification
description: Send notifications to the incident response team or stakeholders

actions:
  - name: send_slack_notification
    description: Send a notification to a Slack channel
    enabled: true
    entry_point: send_slack_notification.py
    runner_type: "python-script"

  - name: send_email_notification
    description: Send a notification via email
    enabled: true
    entry_point: send_email_notification.py
    runner_type: "python-script"
```




- [ ] Создайте новый файл сценария Python send_slack_notification.py внутри пакета:



```
# notification_alerting/actions/send_slack_notification.py

import requests
from st2common.runners.base_action import Action

class SendSlackNotificationAction(Action):
    def run(self, message, channel):
        # Код для отправки уведомления Slack
        # Замените <slack_webhook_url> на ваш фактический URL webhook
        webhook_url = "<slack_webhook_url>"
        payload = {
            "text": message,
            "channel": channel
        }
        response = requests.post(url=webhook_url, json=payload)

        if response.status_code == 200:
            return True
        else:
            return False
```



- [ ] Создайте новый файл сценария Python send_email_notification.py внутри пакета:



```
# notification_alerting/actions/send_email_notification.py

import smtplib
from email.mime.text import MIMEText
from st2common.runners.base_action import Action

class SendEmailNotificationAction(Action):
    def run(self, message, recipient, sender, subject):
        # Код для отправки уведомления по электронной почте
        # Замените <smtp_server>, <smtp_port>, <smtp_username> и <smtp_password> на данные вашего почтового сервера
        smtp_server = "<smtp_server>"
        smtp_port = <smtp_port>
        smtp_username = "<smtp_username>"
        smtp_password = "<smtp_password>"

        email_message = MIMEText(message)
        email_message["Subject"] = subject
        email_message["From"] = sender
        email_message["To"] = recipient

        try:
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.login(smtp_username, smtp_password)
                server.send_message(email_message)
            return True
        except Exception as e:
            return str(e)
```



- [ ] Зарегистрируйте интеграции в файле pack.yaml:


```
# notification_alerting/pack.yaml

integrations:
  - integrations/send_notification.yaml
```



- [ ] Отправьте уведомление в Slack:


```
st2 run send_notification.send_slack_notification message=<notification_message> channel=<slack_channel>
```

- [ ] Отправьте уведомление по электронной почте:

```
st2 run send_notification.send_email_notification message=<notification_message> recipient=<recipient_email> sender=<sender_email> subject=<email_subject> smtp_server=<smtp_server> smtp_port=<smtp_port> smtp_username=<smtp_username> smtp_password=<smtp_password>
```







### Патчи для уязвимых систем:

Описание: Автоматическое исправление уязвимых систем путем выполнения скриптов или запуска инструментов управления конфигурацией, таких как Ansible.

Команда/код: `st2 run remediation.patch`


- [ ] Создайте новый пакет StackStorm:

```
st2 pack create vulnerability_patching
```


- [ ] Создайте новый файл действий patch_vulnerable_systems.yaml внутри пакета:


```
# vulnerability_patching/actions/patch_vulnerable_systems.yaml

name: patch_vulnerable_systems
description: Automatically patch vulnerable systems

runner_type: "remote-shell-script"
enabled: true
entry_point: patch_vulnerable_systems.sh
```


- [ ] Создайте новый файл сценария оболочки patch_vulnerable_systems.sh внутри пакета:



```
# vulnerability_patching/actions/patch_vulnerable_systems.sh

# Код для исправления уязвимых систем с помощью Ansible или других инструментов управления конфигурацией
ansible-playbook -i inventory.ini patch_vulnerable_systems.yml
```


- [ ] Создайте файл плейбука Ansible patch_vulnerable_systems.yml:



```
# vulnerability_patching/actions/patch_vulnerable_systems.yml

- name: Patch vulnerable systems
  hosts: vulnerable_hosts
  tasks:
    - name: Apply security patches
      apt:
        name: "*"
        state: latest
        update_cache: yes
```




- [ ] Зарегистрируйте действие в файле pack.yaml:




```
# vulnerability_patching/pack.yaml

actions:
  - actions/patch_vulnerable_systems.yaml
```






### Изоляция сети:

Описание: Изолируйте взломанные системы от сети, чтобы предотвратить дальнейший ущерб.

Команда/код: `st2 run remediation.isolate`



- [ ] Создайте новый пакет StackStorm:

```
st2 pack create network-isolation
```



- [ ] Создайте новый файл действия

```
st2 action create network_isolation.yaml
```



- [ ] Откройте файл network_isolation.yaml и добавьте в него следующее содержимое:



```
name: network_isolation
description: Isolate compromised systems from the network
runner_type: run-local
parameters:
  - name: ip_address
    description: IP address of the compromised system
    type: string
    required: true
entry_point: isolation.sh
```



- [ ] Откройте файл isolation.sh и добавьте в него следующее содержимое:



```
#!/bin/bash

ip_address="{{ip_address}}"

# Execute commands to isolate the system
iptables -A INPUT -s $ip_address -j DROP
iptables -A OUTPUT -d $ip_address -j DROP
```



- [ ] Зарегистрируйте действие:

```
st2 run packs.setup_virtualenv packs=network-isolation
```




- [ ] Проверьте действие, выполнив его:



```
st2 run network-isolation.network_isolation ip_address=<ip_address>
```



### Блокировка учетной записи пользователя:

Описание: Блокировка учетных записей пользователей, связанных с выявленной уязвимостью, для ограничения доступа.

Команда/код: `st2 run remediation.lock_account`




- [ ] Создайте новый пакет StackStorm:



```
st2 pack create user-account-lockout
```



- [ ] Создайте новый файл действия:



```
st2 action create user_account_lockout.yaml
```



- [ ] Откройте файл user_account_lockout.yaml и добавьте в него следующее содержимое:



```
name: user_account_lockout
description: Lock user accounts associated with the identified vulnerability
runner_type: run-local
parameters:
  - name: username
    description: Username of the user account to lock
    type: string
    required: true
entry_point: lockout.sh
```



- [ ] Откройте файл lockout.sh и добавьте в него следующее содержимое:



```
#!/bin/bash

username="{{username}}"

# Execute commands to lock the user account
usermod -L $username
```



- [ ] Зарегистрируйте действие:



```
st2 run packs.setup_virtualenv packs=user-account-lockout
```



- [ ] Проверьте действие, выполнив



```
st2 run user-account-lockout.user_account_lockout username=<username>
```



### Обновление статуса инцидента:

Описание: Обновление статуса инцидента с предоставлением информации о ходе устранения в режиме реального времени.

Command/Code: `st2 run incident.update_status`




- [ ] Создайте новый пакет StackStorm:



```
st2 pack create incident-status-update
```



- [ ] Создайте новый файл действия



```
st2 action create incident_status_update.yaml
```



- [ ] Откройте файл incident_status_update.yaml и добавьте в него следующее содержимое:



```
name: incident_status_update
description: Update the status of an incident
runner_type: run-local
parameters:
  - name: incident_id
    description: Identifier of the incident
    type: string
    required: true
  - name: status
    description: New status of the incident
    type: string
    required: true
entry_point: status_update.sh
```



- [ ] Откройте файл status_update.sh и добавьте в него следующее содержимое:



```
#!/bin/bash

incident_id="{{incident_id}}"
status="{{status}}"

# Выполнение команд для обновления статуса инцидента.
# Например, обновить систему тикетов, отправить уведомление и т. д.
echo "Incident $incident_id status updated to $status"
```



- [ ] Зарегистрируйте действие:



```
st2 run packs.setup_virtualenv packs=incident-status-update
```



- [ ] Проверьте действие, выполнив его:


```
st2 run incident-status-update.incident_status_update incident_id=<incident_id> status=<new_status>
```



### Разрешение инцидента:

Описание: Закройте инцидент после успешного устранения и сообщите команде о решении.

Команда/код: `st2 run incident.resolve`




- [ ] Создайте новый пакет StackStorm:


```
st2 pack create incident-resolution
```



- [ ] Создайте новый файл действия:


```
st2 action create incident_resolution.yaml
```



- [ ] Откройте файл incident_resolution.yaml и добавьте в него следующее содержимое:


```
name: incident_resolution
description: Resolve an incident and notify the team
runner_type: run-local
parameters:
  - name: incident_id
    description: Identifier of the incident
    type: string
    required: true
entry_point: resolution_script.sh
```



- [ ] Откройте файл resolution_script.sh и добавьте в него следующее содержимое:


```
#!/bin/bash

incident_id="{{incident_id}}"

# Выполнение команд для разрешения инцидента
# Например, закрыть тикет, уведомить команду и т. д.
echo "Incident $incident_id resolved successfully"
```



- [ ] Зарегистрируйте действие:


```
st2 run packs.setup_virtualenv packs=incident-resolution
```



- [ ] Проверьте действие, выполнив его:


```
st2 run incident-resolution.incident_resolution incident_id=<incident_id>
```


## Безопасный пайплайн с использованием декларативного пайплайна Jenkins

```
pipeline {
    agent any
    
    environment {
        DOCKER_REGISTRY = "your_docker_registry"
        DOCKER_CREDENTIALS_ID = "your_docker_credentials_id"
        SONARQUBE_URL = "your_sonarqube_url"
        SONARQUBE_TOKEN = "your_sonarqube_token"
    }
    
    stages {
        stage('Build') {
            steps {
                script {
                    git 'https://github.com/devopscube/declarative-pipeline-examples.git'
                    sh 'mvn clean install'
                }
            }
        }
        
        stage('SonarQube Scan') {
            steps {
                withSonarQubeEnv('SonarQube') {
                    script {
                        sh "mvn sonar:sonar -Dsonar.projectKey=my_project -Dsonar.host.url=${SONARQUBE_URL} -Dsonar.login=${SONARQUBE_TOKEN}"
                    }
                }
            }
        }
        
        stage('Containerize') {
            steps {
                script {
                    sh "docker build -t ${DOCKER_REGISTRY}/my-app:${BUILD_NUMBER} ."
                    sh "docker login -u your_docker_username -p your_docker_password ${DOCKER_REGISTRY}"
                    sh "docker push ${DOCKER_REGISTRY}/my-app:${BUILD_NUMBER}"
                }
            }
        }
        
        stage('Deploy') {
            steps {
                script {
                    sh "kubectl apply -f kube-deployment.yaml"
                }
            }
        }
    }
    
    post {
        success {
            echo "Pipeline executed successfully!"
        }
        
        failure {
            echo "Pipeline execution failed!"
        }
        
        always {
            echo "Cleaning up..."
            sh "docker logout ${DOCKER_REGISTRY}"
        }
    }
}
```

В этом пайплайне этапы включают сборку проекта, сканирование SonarQube, контейнеризацию приложения и его развертывание с помощью Kubernetes.Пайплайн также обрабатывает действия после выполнения, основанные на успехе или неудаче пайплайна.

Убедитесь в том, что вы заменили заполнители на соответствующие значения, такие как `your_docker_registry`, `your_docker_credentials_id`, `your_sonarqube_url`, и `your_sonarqube_token`,  чтобы они соответствовали вашему окружению.





## Ссылки

* https://devopscube.com/declarative-pipeline-parameters/

