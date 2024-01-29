---
layout: default
title:  SCA
parent: Code
---

# SCA
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---




SCA расшифровывается как анализ состава программного обеспечения. Это один из видов тестирования безопасности приложений, который направлен на выявление и управление сторонними компонентами и зависимостями, используемыми в приложении. Инструменты SCA сканируют кодовую базу приложения и артефакты сборки на предмет выявления сторонних библиотек и компонентов, а затем оценивают эти компоненты на предмет известных уязвимостей безопасности или других проблем.


Процесс SCA обычно включает следующие этапы:

1. **Обнаружение**: Инструмент SCA сканирует кодовую базу приложения и артефакты сборки, чтобы выявить все сторонние библиотеки и компоненты, используемые в приложении.

2. **Инвентаризация**: Инструмент SCA создает список всех сторонних компонентов и библиотек, используемых в приложении, включая их версии, типы лицензий и все известные уязвимости и проблемы безопасности.

3. **Оценка**: Инструмент SCA оценивает каждый компонент в инвентаре на предмет известных уязвимостей безопасности или других проблем, используя такие источники, как Национальная база данных уязвимостей (NVD) и базы данных Common Vulnerabilities and Exposures (CVE).

4. **Устранение**: На основе результатов оценки инструмент SCA может предоставить рекомендации по устранению проблем, например, обновить компонент до новой версии или перейти на другой компонент, более безопасный.

Выполняя SCA, организации могут получить информацию о компонентах и библиотеках сторонних разработчиков, используемых в приложениях, и проактивно управлять любыми уязвимостями и проблемами безопасности, связанными с этими компонентами. Это поможет повысить общую безопасность и устойчивость приложения.

Инструменты SCA работают путем сканирования кодовой базы и выявления компонентов с открытым исходным кодом, которые используются в приложении. Затем они сравнивают этот список с известными уязвимостями в своей базе данных и предупреждают вас о найденных уязвимостях. Это поможет вам управлять компонентами с открытым исходным кодом и убедиться, что вы не используете уязвимые компоненты в своем приложении.






| SCA инструменты    | Описание   | Поддерживаемые языки |
|:---------------|:---------------------|:---------------------|
| `Sonatype Nexus Lifecycle	` | Программное средство автоматизации и управления цепочками поставок	 | Java, .NET, Ruby, JavaScript, Python, Go, PHP, Swift |
| `Black Duck` | Инструмент управления безопасностью и соблюдением лицензионных требований с открытым исходным кодом	 | Более 20 языков, включая Java, .NET, Python, Ruby, JavaScript, PHP |
| `WhiteSource` | Облачный инструмент для управления безопасностью и соблюдением лицензионных требований с открытым исходным кодом	 | Более 30 языков, включая Java, .NET, Python, Ruby, JavaScript, PHP |
| `Snyk` | Инструмент управления безопасностью и зависимостями, ориентированный на разработчиков	 | Более 40 языков, включая Java, .NET, Python, Ruby, JavaScript, PHP, Go |
| `FOSSA` | Инструмент для разработки программного обеспечения, автоматизирующий соблюдение лицензионных требований к открытому исходному коду и управление уязвимостями	 | Более 30 языков, включая Java, .NET, Python, Ruby, JavaScript, PHP |





Вот пример использования SCA в конвейере CI/CD:

1. Выберите инструмент SCA: На рынке доступно несколько инструментов SCA, таких как Snyk, Black Duck и WhiteSource. Вам нужно выбрать SCA-инструмент, который совместим с вашим стеком приложений и предоставляет необходимые функции.

2. Интегрируйте инструмент в конвейер CI/CD: Выбрав SCA-инструмент, необходимо интегрировать его в конвейер CI/CD. Это можно сделать, добавив в конвейер шаг, который запускает SCA-инструмент и сообщает о результатах.

3. Настройте инструмент: Необходимо настроить инструмент SCA на сканирование кода приложения и выявление компонентов с открытым исходным кодом, которые используются в вашем приложении. Это можно сделать, предоставив инструменту доступ к репозиторию исходного кода и указав зависимости вашего приложения.

4. Проанализируйте результаты: После того как SCA-инструмент закончит сканирование вашей кодовой базы, он создаст отчет о компонентах с открытым исходным кодом, которые используются в вашем приложении, и о всех уязвимостях, которые связаны с этими компонентами. Вам необходимо проанализировать отчет и принять меры по устранению выявленных уязвимостей.

5. Устраните уязвимости: Если уязвимости обнаружены, необходимо устранить их, либо обновив уязвимые компоненты, либо удалив их из приложения.


Вот пример конвейера CI/CD, включающего этап SCA:


```
name: MyApp CI/CD Pipeline

on:
  push:
    branches: [ master ]

jobs:
  build:
    runs-on: ubuntu-latest

    steps:
    - name: Checkout code
      uses: actions/checkout@v2

    - name: Build and test
      run: |
        npm install
        npm test

    - name: Run SCA
      uses: snyk/actions@v1
      with:
        file: package.json
        args: --severity-threshold=high

    - name: Deploy to production
      if: github.ref == 'refs/heads/master'
      run: deploy.sh

```


В этом примере инструмент SCA интегрирован в конвейер с помощью Snyk GitHub Action. Инструмент настроен на сканирование файла package.json и сообщение о любых уязвимостях с порогом серьезности "высокий". Если уязвимости будут обнаружены, конвейер завершится неудачей, а разработчик будет уведомлен о необходимости принять меры.




## Проверка зависимостей OWASP


1- Выполните сканирование локального проекта

```
dependency-check.sh --scan <path/to/project>
```


2- Сканирование проекта Maven

```
dependency-check.sh --scan <path/to/pom.xml>
```


3- Сканирование проекта Gradle

```
dependency-check.sh --scan <path/to/build.gradle>
```


4- Выполните сканирование локального проекта

```
dependency-check.sh --updateonly
```


5- Укажите строку подключения к базе данных

```
dependency-check.sh --scan <path/to/project> --connectionString <db-connection-string>
```

6- Укажите порог серьезности CVSS

```
dependency-check.sh --scan <path/to/project> --suppression <suppression-file>
```

7- Укажите формат вывода

```
dependency-check.sh --scan <path/to/project> --format <output-format>
```



## scancode-toolkit


1. Установите scancode-toolkit:

```
pip install scancode-toolkit
```


2. Выполните сканирование определенного проекта или каталога

```
scancode <path-to-project>
```

3. Создание отчета о сканировании в формате JSON

```
scancode --json-pp <path-to-project> > report.json
```

4. Исключите определенные лицензии из сканирования

```
scancode --license-exclude <license-name> <path-to-project>
```



## Управление зависимостями Nexus

1. Установите менеджер репозиториев Nexus 

```
wget <nexus_download_url> -O nexus.zip
unzip nexus.zip  
cd nexus-x.x.x ./bin/nexus start
```

2. Настройка менеджера репозиториев Nexus 

Open web browser and access `http://localhost:8081`



{: .note }
Integrate vulnerability scanning tools like OWASP Dependency Check or Sonatype Nexus IQ with Nexus Repository Manager. These tools can analyze your dependencies for known security vulnerabilities and provide actionable insights to mitigate risks. Regularly scan your repositories for vulnerabilities and apply patches or upgrade dependencies as necessary.


{: .note }
Continuous Integration and Deployment (CI/CD) Integration: Integrate Nexus Repository Manager with your CI/CD pipelines to automate dependency management. Use build tool plugins or APIs provided by Nexus Repository Manager to fetch dependencies and publish artifacts seamlessly within your build and deployment processes.


### Dependency Vulnerability Management

Integrate Nexus Lifecycle or Nexus IQ into your CI/CD pipeline to scan and analyze dependencies for vulnerabilities.

```
# .gitlab-ci.yml
stages:
  - build
  - test

scan_dependencies:
  stage: build
  image: maven:3.8.4
  script:
    - mvn org.sonatype.plugins:nexus-staging-maven-plugin:1.6.8:rc-list -B
    - mvn org.sonatype.plugins:nexus-staging-maven-plugin:1.6.8:rc-open -B
    - mvn clean package
    - mvn org.sonatype.plugins:nexus-staging-maven-plugin:1.6.8:rc-close -B
  only:
    - master
```

### License Compliance

Code: Integrate Nexus Lifecycle or Nexus IQ to scan and enforce license compliance.

```
# Jenkinsfile
pipeline {
  agent any
  stages {
    stage('Build') {
      steps {
        sh 'mvn clean install'
      }
    }
    stage('Scan Licenses') {
      steps {
        sh 'mvn org.sonatype.plugins:nexus-staging-maven-plugin:1.6.8:rc-list'
        // Perform license compliance checks
        sh 'mvn org.sonatype.plugins:nexus-staging-maven-plugin:1.6.8:rc-close'
      }
    }
  }
}
```

Configuration: Configure Nexus Repository Manager to enforce license policies and restrictions.

```
<!-- pom.xml -->
<project>
  <build>
    <plugins>
      <plugin>
        <groupId>org.sonatype.plugins</groupId>
        <artifactId>nexus-staging-maven-plugin</artifactId>
        <version>1.6.8</version>
      </plugin>
    </plugins>
  </build>
</project>
```

### Continuous Monitoring

Code: Implement continuous monitoring and scanning of your CI/CD pipeline for security vulnerabilities and compliance issues.

```
# .travis.yml
language: java
script:
  - mvn clean install
  - mvn org.sonatype.plugins:nexus-staging-maven-plugin:1.6.8:rc-list
  # Run additional security scans and tests
  - mvn org.sonatype.plugins:nexus-staging-maven-plugin:1.6.8:rc-close
```

Configuration: Set up automated alerts and notifications for any security or compliance issues detected during the CI/CD process.

```
<!-- pom.xml -->
<project>
  <build>
    <plugins>
      <plugin>
        <groupId>org.sonatype.plugins</groupId>
        <artifactId>nexus-staging-maven-plugin</artifactId>
        <version>1.6.8</version>
        <configuration>
          <!-- Nexus Repository URL -->
          <serverId>nexus-server</serverId>
          <nexusUrl>https://nexus.example.com</nexusUrl>
          <autoReleaseAfterClose>true</autoReleaseAfterClose>
        </configuration>
        <executions>
          <execution>
            <id>default-deploy</id>
            <phase>deploy</phase>
            <goals>
              <goal>deploy</goal>
            </goals>
          </execution>
        </executions>
      </plugin>
    </plugins>
  </build>
  <!-- Other project configurations -->
</project>
```









