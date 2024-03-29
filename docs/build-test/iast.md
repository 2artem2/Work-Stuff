---
layout: default
title: IAST
parent: Build & Test
---

# IAST- Интерактивное тестирование безопасности приложений
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---


IAST расшифровывается как Interactive Application Security Testing. Это тип тестирования безопасности приложений, который сочетает в себе преимущества инструментов SAST (Static Application Security Testing) и DAST (Dynamic Application Security Testing).

Инструменты IAST предназначены для интеграции в тестируемое приложение и работают путем инструментального анализа кода приложения, обеспечивая обратную связь в режиме реального времени по любым уязвимостям безопасности, выявленным во время выполнения. Это позволяет инструментам IAST обнаруживать уязвимости, которые могут быть не видны при других видах тестирования, например те, которые возникают из-за конфигурации приложения или его окружения.

Вот некоторые ключевые особенности IAST:

1. Обратная связь в реальном времени: Инструменты IAST предоставляют информацию об уязвимостях безопасности в режиме реального времени по мере их обнаружения во время выполнения, что позволяет разработчикам устранять их по мере обнаружения.

2. Точность: инструменты IAST обладают высокой степенью точности, поскольку способны обнаруживать уязвимости в контексте среды выполнения приложения.

3. Низкий процент ложных срабатываний: Инструменты IAST имеют низкий процент ложных срабатываний, поскольку они способны отличить реальные уязвимости от доброкачественного кода.

4. Интеграция: Инструменты IAST могут быть интегрированы в процесс разработки, что позволяет разработчикам включать тестирование безопасности в свои рабочие процессы.

5. Автоматизация: Инструменты IAST могут быть автоматизированы, что позволяет проводить непрерывное тестирование и быстрее получать информацию об уязвимостях.

6. Покрытие: Инструменты IAST могут обеспечить покрытие широкого спектра уязвимостей безопасности, включая те, которые трудно обнаружить с помощью других видов тестирования.


| IAST Инструмент    | Описание   | 
|:---------------|:---------------------|
| `Contrast Security` | инструмент IAST, который автоматически выявляет и отслеживает уязвимости в режиме реального времени в процессе разработки программного обеспечения. Его можно интегрировать в конвейер CI/CD для обеспечения непрерывного мониторинга и защиты.	 | 
| `Hdiv Security` | решение IAST, которое обнаруживает и предотвращает атаки, отслеживая поведение приложений во время выполнения. Оно предоставляет подробную информацию об уязвимостях и генерирует отчеты для разработчиков и команд безопасности.	 | 
| `RIPS Technologies` | инструмент тестирования безопасности, сочетающий в себе IAST и SAST (Static Application Security Testing) для всестороннего анализа безопасности веб-приложений. Он поддерживает множество языков программирования и фреймворков.	 | 
| `Acunetix` | инструмент для обеспечения безопасности веб-приложений, предлагающий возможности IAST для обнаружения уязвимостей в режиме реального времени. Он предоставляет подробные отчеты и интегрируется с конвейерами CI/CD для автоматизации процесса тестирования безопасности.	 | 
| `AppSecEngineer` | инструмент IAST с открытым исходным кодом для обнаружения и предотвращения уязвимостей в веб-приложениях. Он интегрируется с такими популярными веб-фреймворками, как Spring, Django и Ruby on Rails, и предоставляет подробные отчеты об уязвимостях и попытках атак.	 | 



пример пайплайна CI/CD с IAST с использованием Contrast Security:

```
stages:
  - build
  - test
  - iast
  - deploy

build:
  stage: build
  script:
    - mvn clean package

test:
  stage: test
  script:
    - mvn test

iast:
  stage: iast
  image: contrastsecurity/contrast-agent
  script:
    - java -javaagent:/opt/contrast/contrast.jar -jar target/myapp.jar
  allow_failure: true

deploy:
  stage: deploy
  script:
    - mvn deploy
  only:
    - master
```

В этом конвейере этап IAST добавляется после этапа тестирования. Сценарий на этапе IAST запускает агент Contrast Security с помощью команды Java с опцией `-javaagent`, а затем запускает приложение с помощью команды `jar`. Агент будет отслеживать приложение на предмет уязвимостей в системе безопасности и предоставлять обратную связь в режиме реального времени.

Обратите внимание, что это всего лишь пример конвейера, и его можно настроить в соответствии с вашими потребностями. Кроме того, не забудьте правильно настроить инструмент IAST и следовать лучшим практикам безопасной разработки и развертывания.
