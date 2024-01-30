---
layout: default
title: Model Robustness and Adversarial Attacks
parent: MlSecOps
---

# Устойчивость моделей и атаки противника
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---



Оценка и повышение устойчивости моделей машинного обучения к атакам противника. Это включает в себя тестирование моделей в различных сценариях, разработку средств защиты от атак (например, обучение противника) и понимание ограничений устойчивости моделей.



## OWASP Стандарт проверки безопасности машинного обучения (MLSVS)


- [ ] Ознакомьтесь с MLSVS  

Прочитайте документацию по MLSVS, доступную на сайте OWASP.

- [ ] Оценка модели угроз

Проведите моделирование угроз, чтобы определить потенциальные риски и угрозы безопасности в вашей системе машинного обучения.

- [ ] Проверка данных для обучения модели. Выполните проверку данных и целостности набора данных для обучения, чтобы обеспечить его качество и предотвратить несанкционированное вмешательство.

- [ ] Проверка процесса подготовки модели. Проверьте меры безопасности, реализованные в процессе подготовки модели, такие как контроль доступа, создание версий и безопасное хранение.

- [ ] Оценка устойчивости модели. Протестируйте модель против различных методов атак, таких как атаки-обманки, атаки отравления и аварские входы, чтобы оценить ее устойчивость.

- [ ] Проверка объяснений модели. Проверьте интерпретируемость и объяснимость предсказаний модели, чтобы обеспечить прозрачность и подотчетность.

- [ ] Оценка безопасности развертывания модели. Оцените средства контроля безопасности, реализованные при развертывании модели машинного обучения, включая средства контроля доступа, аутентификации и шифрования.

- [ ] Мониторинг производительности модели. Создайте механизмы мониторинга для обнаружения и смягчения последствий снижения производительности модели, дрейфа данных и атак противника в режиме реального времени.

- [ ] Реализация защиты конфиденциальности. Применяйте методы сохранения конфиденциальности, такие как дифференциальная конфиденциальность, анонимизация или федеративное обучение, для защиты конфиденциальных данных, используемых в системе машинного обучения.

- [ ] Регулярно обновляйте практические рекомендации MLSVS. Следите за последними рекомендациями и лучшими практиками MLSVS, чтобы адаптироваться к изменяющимся угрозам безопасности машинного обучения.


## Безопасность цепочки поставок для MLSecOps

* **Установите Sigstore**

```
# Клонируйте репозиторий Sigstore
git clone https://github.com/sigstore/sigstore

# Перейдите в каталог Sigstore
cd sigstore

# Установите Sigstore CLI
make install
```

* **Генерация и управление криптографическими ключами**

```
# Создайте новую пару ключей
sigstore keygen

# Список доступных ключей
sigstore key list

# Установите активный ключ
sigstore key set <key-id>
```

* **Подписать артефакт программного обеспечения**

```
# Подпишите программный артефакт с помощью активного ключа
sigstore sign <artifact-file>
```

* **Проверка подписи подписанного артефакта:**

```
# Проверка подписи подписанного артефакта
sigstore verify <signed-artifact-file>
```

* **Интеграция Sigstore в цепочку поставок**

Sigstore можно интегрировать в различные этапы цепочки поставок, например, во время разработки, сборки, развертывания и распространения программного обеспечения. Например, вы можете настроить конвейер CI/CD так, чтобы он подписывал артефакты с помощью Sigstore после успешной сборки и проверял подписи во время развертывания.


* **Пример из реальной жизни**

Допустим, у вас есть файл модели машинного обучения с именем "model.pkl", который вы хотите подписать и проверить с помощью Sigstore:

```
# Подпишите файл модели
sigstore sign model.pkl

# В результате будет создан подписанный файл артефакта с именем "model.pkl.sig".

# Проверьте подпись подписанного файла модели
sigstore verify model.pkl.sig
```

Подписывая и проверяя файл модели с помощью Sigstore, вы можете гарантировать его целостность и подлинность на протяжении всей цепочки поставок программного обеспечения.





## Kubeflow

* **Настройка среды**

Настройте кластер Kubernetes для развертывания Kubeflow.

```
# Создание кластера Kubernetes с помощью облачного провайдера
gcloud container clusters create my-cluster --num-nodes=3 --zone=us-central1-a

# Установите Kubeflow с помощью инструмента развертывания Kubeflow
kfctl init my-kubeflow-app --platform gcp --project=my-project
kfctl generate all -V
kfctl apply all -V
```



* **Разработка модели**

Разработайте ML-модель с помощью TensorFlow и упакуйте ее в контейнер Docker.

```
# Создайте Dockerfile для создания контейнера модели
FROM tensorflow/tensorflow:latest
COPY model.py /app/
WORKDIR /app/
CMD ["python", "model.py"]

# Сборка и маркировка образа Docker
docker build -t my-model-image .
```


* **Контроль версий**

Отслеживайте ML-код и артефакты с помощью Git для воспроизводимости и прослеживаемости.

```
# Инициализация репозитория Git
git init

# Добавьте код и артефакты ML
git add .

# Внести изменения
git commit -m "Initial commit"
```

* **Непрерывная интеграция и непрерывное развертывание (CI/CD)**

Настройка пайплайна CI/CD для автоматизированной сборки, тестирования и развертывания ML-моделей.

```
# Настройка пайплайна Jenkins для ML-модели
pipeline {
  agent any
  stages {
    stage('Build') {
      steps {
        // Build Docker image
        sh 'docker build -t my-model-image .'
      }
    }
    stage('Test') {
      steps {
        // Run unit tests
        sh 'python -m unittest discover tests'
      }
    }
    stage('Deploy') {
      steps {
        // Deploy model to Kubeflow
        sh 'kubectl apply -f deployment.yaml'
      }
    }
  }
}
```

* **Сканирование безопасности**

Интегрируйте инструменты сканирования безопасности для выявления уязвимостей в ML-коде и зависимостях.

```
# Установите Snyk CLI
npm install -g snyk

# Сканирование образа Docker на наличие уязвимостей
snyk test my-model-image
```

* **Обучение моделей**

Используйте конвейеры Kubeflow для определения и выполнения рабочих процессов ML.

```
# Определите конвейер Kubeflow для обучения
@dsl.pipeline(name='Training Pipeline', description='Pipeline for model training')
def train_pipeline():
    ...

# Компиляция и запуск пайплайна
kfp.compiler.Compiler().compile(train_pipeline, 'pipeline.tar.gz')
kfp.Client().create_run_from_pipeline_package('pipeline.tar.gz')
```

* **Обслуживание моделей**

Разверните обученные модели как сервисы Kubernetes с помощью Kubeflow Serving.

```
# Развертывание обученной модели в виде сервиса
kubectl apply -f serving.yaml
```

* **Мониторинг и наблюдаемость**

Используйте инструменты мониторинга и протоколирования для отслеживания производительности и поведения моделей ML в режиме реального времени. Это помогает обнаруживать аномалии, следить за использованием ресурсов и обеспечивать общее состояние системы ML.

```
# Установите Prometheus и Grafana с помощью Helm
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update
helm install prometheus prometheus-community/prometheus
helm install grafana grafana/grafana

# Получите доступ к приборной панели Grafana
kubectl port-forward service/grafana 3000:80

# Настройка Prometheus в качестве источника данных в Grafana и создание панелей мониторинга ML-моделей
```

* **Автоматизированное тестирование**

Внедрите автоматизированное тестирование моделей ML для обеспечения их корректности и производительности. Это может включать модульные тесты, интеграционные тесты и нагрузочные тесты для проверки поведения ваших моделей.

```
# Установите PyTest
pip install pytest

# Написание тестов для ML-моделей
# Пример теста:
def test_model_prediction():
    model = load_model('my-model.h5')
    input_data = ...
    expected_output = ...
    prediction = model.predict(input_data)
    assert np.allclose(prediction, expected_output, atol=1e-5)

# Выполните тесты
pytest tests/
```



* **Аудит и соответствие**

Внедрите контрольные журналы и меры по обеспечению соответствия для отслеживания изменений в модели, использования данных и производительности модели. Это поможет выполнить нормативные требования и обеспечит прозрачность и подотчетность ваших операций ML.

```
# Определите и внедрите механизмы аудита.
# Пример:
- Keep track of model versions and associated metadata (e.g., timestamp, author, changes made).
- Implement data access logs to monitor data usage and permissions.
- Establish model performance metrics and logging for compliance monitoring.
- Regularly review and update auditing and compliance measures based on regulatory standards.
```





## Chef InSpec



### Выполните базовую проверку соответствия

Выполните проверку соответствия с помощью InSpec на целевой системе.


```
inspec exec <path_to_profile>
```

пример профиля InSpec, который можно использовать для выполнения проверки соответствия целевой системы:

```
# my_compliance_profile.rb

# Определите метаданные профиля
title 'My Compliance Profile'
maintainer 'Your Name'
license 'Apache-2.0'
description 'Compliance checks for the target system'

# Определите целевую систему (системы) для проверки
target_hostname = attribute('target_hostname', description: 'Hostname of the target system')

# Начните писать элементы управления для проверки соответствия
control 'check_os_version' do
  impact 0.7
  title 'Operating System Version Check'
  desc 'Verify that the operating system version meets the compliance requirements'
  
  only_if { os.linux? } # Run this control only on Linux systems

  describe command('uname -r') do
    its('stdout') { should cmp '4.19.0-10-amd64' } # Replace with the desired OS version
  end
end

control 'check_secure_password_policy' do
  impact 0.5
  title 'Secure Password Policy Check'
  desc 'Ensure that the system enforces a secure password policy'
  
  describe file('/etc/login.defs') do
    its('content') { should match(/PASS_MAX_DAYS\s+(\d+)/) }
    its('content') { should match(/PASS_MIN_LEN\s+(\d+)/) }
    # Add more password policy checks as required
  end
end

# При необходимости добавьте дополнительные элементы управления...
```

В этом примере профиль состоит из двух элементов управления: одного для проверки версии операционной системы и другого для проверки политики безопасных паролей. Вы можете добавить в профиль больше элементов управления в зависимости от требований соответствия.

Чтобы использовать этот профиль, создайте новый файл с расширением .rb (например, my_compliance_profile.rb) и скопируйте в него код. Настройте элементы управления в соответствии с вашими специфическими проверками и требованиями соответствия.



### Создание отчета о соответствии

Запустите проверку на соответствие и создайте отчет в определенном формате.


```
inspec exec <path_to_profile> --reporter <reporter_name>
```


### Проверка конкретного элемента управления в профиле

Выполните проверку соответствия для определенного элемента управления в профиле.

```
inspec exec <path_to_profile> --controls <control_name>
```

### Укажите имя целевого узла/IP для проверки соответствия

Запуск проверки соответствия на конкретной целевой системе.

```
inspec exec <path_to_profile> -t <target_hostname_or_ip>
```


### Режим разработки профиля

Включите режим разработки профилей, чтобы в интерактивном режиме писать и тестировать элементы управления.


```
inspec init profile <profile_directory>
inspec shell
```

## envd


### Создайте файл конфигурации:

```
cp config.yml.example config.yml
```


### Запустите службу envd


```
python envd.py
```

### API

Конечные точки API:

* /environments:
  GET: Получить список всех сред.
  POST: Создать новое окружение.
* /environments/{env_id}:
  GET: Получение сведений о конкретном окружении.
  PUT: Обновить существующее окружение.
  DELETE: удалить окружение.
* /environments/{env_id}/variables:
  GET: Получение списка переменных для конкретного окружения.
  POST: Добавить новую переменную в окружение.
* /environments/{env_id}/variables/{var_id}:
  GET: Получение подробной информации о конкретной переменной.
  PUT: Обновить существующую переменную.
  DELETE: удалить переменную.

#### Создайте новую среду

```
curl -X POST -H "Content-Type: application/json" -d '{"name": "Production", "description": "Production environment"}' http://localhost:5000/environments
```

#### Получить список сред

```
curl -X GET http://localhost:5000/environments
```

#### Обновление среды

```
curl -X PUT -H "Content-Type: application/json" -d '{"description": "Updated description"}' http://localhost:5000/environments/{env_id}
```

#### Удалить переменную

```
curl -X DELETE http://localhost:5000/environments/{env_id}/variables/{var_id}
```



## Непрерывное машинное обучение (CML)


### Безопасная публикация артефактов модели

```
name: Publish Model
on:
  push:
    branches:
      - main
jobs:
  publish_model:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v2
      - name: Build Model
        run: |
          # Выполняйте команды для построения и обучения модели
          python train.py
      - name: Publish Model Artifacts
        uses: iterative/cml@v1
        with:
          command: cml-publish model
          files: model.h5
```

Этот пример демонстрирует, как безопасно опубликовать артефакты модели после построения и обучения модели машинного обучения. Действие cml-publish используется для публикации файла model.h5 в качестве артефакта.


### Выполнение сканирования системы безопасности

```
name: Run Security Scans
on:
  push:
    branches:
      - main
jobs:
  security_scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v2
      - name: Run Security Scan
        uses: iterative/cml@v1
        with:
          command: cml-run make scan
```

Этот пример демонстрирует, как запустить сканирование безопасности вашей кодовой базы. Действие cml-run используется для выполнения команды make scan, которая может запустить инструменты сканирования безопасности для анализа кода на наличие уязвимостей.


### Автоматизированный обзор кода

```
name: Automated Code Review
on:
  pull_request:
jobs:
  code_review:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v2
      - name: Run Code Review
        uses: iterative/cml@v1
        with:
          command: cml-pr review
          args: "--checkstyle"
```

Этот пример демонстрирует, как выполнять автоматические проверки кода в запросах на исправление. Действие cml-pr используется для запуска проверки кода с помощью опции --checkstyle, что позволяет обеспечить соблюдение стандартов и лучших практик кодирования.

### Секретное управление

```
name: Secret Management
on:
  push:
    branches:
      - main
jobs:
  secret_management:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v2
      - name: Retrieve Secrets
        uses: iterative/cml@v1
        with:
          command: cml-secrets pull
          args: "--all"
      - name: Build and Deploy
        run: |
          # Используйте полученные секреты для создания и развертывания приложения
          echo $API_KEY > api_key.txt
          python deploy.py
      - name: Cleanup Secrets
        uses: iterative/cml@v1
        with:
          command: cml-secrets clear
          args: "--all"
```

Этот пример демонстрирует, как безопасно управлять секретами во время конвейера CI/CD. Действие cml-secrets используется для извлечения секретов, таких как ключ API, из безопасного хранилища и их использования в процессе сборки и развертывания. После этого секреты очищаются, чтобы минимизировать воздействие.

### Безопасное развертывание с помощью обзора

```
name: Secure Deployment
on:
  push:
    branches:
      - main
jobs:
  secure_deployment:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v2
      - name: Build and Test
        run: |
          # Выполняйте команды для сборки и тестирования приложения
          python build.py
          python test.py
      - name: Request Deployment Review
        uses: iterative/cml@v1
        with:
          command: cml-pr request
          args: "--title 'Deployment Review' --body 'Please review the deployment' --assign @security-team"
```


В этом примере показано, как запросить проверку развертывания у команды безопасности перед развертыванием приложения. Действие cml-pr используется для создания запроса на извлечение с определенным названием, телом и назначенным лицом. Это позволяет команде безопасности просмотреть и утвердить развертывание до его выполнения.


## Автоматизация жизненного цикла машинного обучения

https://github.com/microsoft/nni



## Ресурсы

* https://github.com/devopscube/how-to-mlops
* https://github.com/aws/studio-lab-examples
* https://github.com/fuzzylabs/awesome-open-mlops









