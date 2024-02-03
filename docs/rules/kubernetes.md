---
layout: default
title: Kubernetes
parent: Rules
---

# Kubernetes
{: .no_toc }



## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---




## Учетная запись с жестким кодом

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
# Noncompliant code
apiVersion: v1
kind: Deployment
metadata:
  name: my-app
spec:
  replicas: 3
  template:
    metadata:
      labels:
        app: my-app
    spec:
      containers:
      - name: my-app-container
        image: my-app:v1
        ports:
        - containerPort: 8080
        env:
        - name: DATABASE_URL
          value: "mysql://root:password@localhost:3306/my_database"
```

В этом несоответствующем коде файл конфигурации развертывания Kubernetes Deployment содержит жестко закодированную строку подключения к базе данных в разделе env. URL-адрес базы данных, включая имя пользователя (root), пароль (password) и другие конфиденциальные данные, непосредственно встроен в конфигурационный файл. Такой подход создает риски для безопасности, поскольку конфиденциальная информация раскрыта и может быть легко скомпрометирована, если к конфигурационному файлу получат доступ неавторизованные пользователи.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
# Compliant code
apiVersion: v1
kind: Deployment
metadata:
  name: my-app
spec:
  replicas: 3
  template:
    metadata:
      labels:
        app: my-app
    spec:
      containers:
      - name: my-app-container
        image: my-app:v1
        ports:
        - containerPort: 8080
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: my-app-secrets
              key: database-url
```


В соответствующем коде строка подключения к базе данных заменена ссылкой на секрет Kubernetes. Секрет, названный my-app-secrets, содержит конфиденциальную информацию, такую как URL базы данных, имя пользователя и пароль. Поле valueFrom в секции env предписывает Kubernetes получить значение ключа database-url из указанного Secret.

Используя секреты, вы можете централизовать и безопасно управлять конфиденциальной информацией в Kubernetes, предотвращая уязвимости в жестком коде. Секреты можно шифровать, контролировать доступ и поворачивать, что гораздо проще, чем жестко закодированные значения.

Убедитесь, что вы следуете безопасным методам управления секретами, таким как предоставление соответствующих разрешений, шифрование секретов в состоянии покоя и при передаче, регулярная ротация секретов и использование Kubernetes RBAC (Role-Based Access Control) для контроля доступа к секретам.

Используя секреты для хранения и получения конфиденциальной информации, вы повышаете безопасность, удобство обслуживания и переносимость развертываний Kubernetes.








## Нападение с целью побега из контейнера

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
  - name: privileged-container
    image: my-image
    securityContext:
      privileged: true
```

Несоответствующий код устанавливает флаг privileged в true, что позволяет контейнеру работать с расширенными привилегиями, облегчая злоумышленнику выход из контейнера и получение доступа к хосту.





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
apiVersion: v1
kind: Pod
metadata:
  name: restricted-pod
spec:
  containers:
  - name: restricted-container
    image: my-image
    securityContext:
      privileged: false
```

Соответствующий код устанавливает флаг privileged в false, что ограничивает запуск контейнера с расширенными привилегиями, снижая риск атак на выход из контейнера.




## Атака на сервер API Kubernetes

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
apiVersion: v1
kind: ServiceAccount
metadata:
  name: privileged-service-account
  namespace: default
```

Несоответствующий требованиям код создает привилегированную учетную запись службы без указания каких-либо ограничений RBAC (Role-Based Access Control), что позволяет этой учетной записи иметь широкий доступ к серверу Kubernetes API.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
apiVersion: v1
kind: ServiceAccount
metadata:
  name: restricted-service-account
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: restricted-role
  namespace: default
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: restricted-role-binding
  namespace: default
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: restricted-role
subjects:
- kind: ServiceAccount
  name: restricted-service-account
  namespace: default
```

Соответствующий код создает ограниченную учетную запись службы и применяет правила RBAC для ограничения ее доступа. В этом примере учетной записи службы предоставляются разрешения только на получение, список и просмотр стручков, что обеспечивает более безопасную конфигурацию.



## Сетевая атака Pod-to-Pod

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
apiVersion: v1
kind: Pod
metadata:
  name: unsecured-pod
spec:
  containers:
  - name: container-a
    image: image-a
  - name: container-b
    image: image-b
```

Код, не соответствующий требованиям, развертывает два контейнера в одном поде, без каких-либо сетевых политик или ограничений, позволяя неограниченно взаимодействовать между контейнерами.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
apiVersion: v1
kind: Pod
metadata:
  name: secured-pod
spec:
  containers:
  - name: container-a
    image: image-a
  - name: container-b
    image: image-b
  networkPolicy:
    podSelector:
      matchLabels:
        app: secured-pod
    ingress:
    - from:
        podSelector:
          matchLabels:
            app: secured-pod
```

Соответствующий код вводит сетевые политики для ограничения связи между контейнерами внутри пода. В этом примере контейнер-a и контейнер-b являются частью защищенного блока, и сетевая политика гарантирует, что только поды, помеченные как secured-pod, могут инициировать входящий трафик в этот блок. Такая настройка ограничивает площадь атаки и предотвращает несанкционированный доступ или перехват сетевого трафика из других подов.



## Атака на повышение привилегий

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
  - name: privileged-container
    image: my-image
    securityContext:
      runAsUser: 0
```

Несоответствующий код устанавливает поле runAsUser в 0, что запускает контейнер от имени пользователя root, предоставляя ему широкие привилегии и увеличивая риск атак с повышением привилегий.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
apiVersion: v1
kind: Pod
metadata:
  name: restricted-pod
spec:
  containers:
  - name: restricted-container
    image: my-image
    securityContext:
      runAsUser: 1000
```

Соответствующий код устанавливает в поле runAsUser значение не корневого пользователя (например, UID 1000), что снижает привилегии контейнера и уменьшает риск атак с повышением привилегий.


## Атака на отказ в обслуживании (DoS)

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
apiVersion: v1
kind: Deployment
metadata:
  name: resource-hungry-app
spec:
  replicas: 5
  template:
    spec:
      containers:
      - name: resource-hungry-container
        image: my-image
        resources:
          requests:
            cpu: "1000m"
            memory: "2Gi"
```

Несоответствующий код задает запросы на ресурсы, значительно превышающие необходимые, что может привести к исчерпанию ресурсов и потенциальным DoS-атакам.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
apiVersion: v1
kind: Deployment
metadata:
  name: optimized-app
spec:
  replicas: 5
  template:
    spec:
      containers:
      - name: optimized-container
        image: my-image
        resources:
          requests:
            cpu: "100m"
            memory: "256Mi"
```

Соответствующий код устанавливает более подходящие значения для запросов ресурсов, гарантируя, что каждый контейнер потребляет только необходимое количество ресурсов процессора и памяти, снижая риск DoS-атак.
