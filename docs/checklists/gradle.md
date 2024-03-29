---
layout: default
title: Gradle
parent: Checklists
---

# Усиление Gradle для DevSecOps
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Список лучших практик по защите Gradle для DevSecOps


### Используйте последнюю стабильную версию Gradle	



Проверьте последнюю версию на официальном сайте: https://gradle.org/releases/, а затем установите ее. Например: wget https://services.gradle.org/distributions/gradle-7.0.2-bin.zip, разархивируйте gradle-7.0.2-bin.zip и установите переменную окружения PATH на каталог Gradle bin.



### Отключите или ограничьте работу демона Gradle	


Вы можете отключить демон, добавив в файл gradle.properties следующую строку: org.gradle.daemon=false. Также вы можете ограничить максимальный объем памяти, который может использовать демон, установив свойство org.gradle.jvmargs.


### Настройте Gradle на использование HTTPS для всех репозиториев	

Добавьте следующий код в файл build.gradle, чтобы обеспечить использование HTTPS для всех репозиториев:

```
allprojects {
    repositories {
        mavenCentral {
            url "https://repo1.maven.org/maven2/"
        }
        maven {
            url "https://plugins.gradle.org/m2/"
        }
    }
}

```


### Используйте безопасные учетные данные для доступа к репозиториям

Используйте зашифрованные учетные данные в файле `build.gradle` или переменных окружения для доступа к репозиториям.


### Используйте плагины и зависимости только из проверенных источников

Используйте плагины и зависимости из официальных источников и избегайте использования плагинов и зависимостей из неизвестных или недоверенных источников. 


### Реализация контроля доступа для сборок Gradle

Реализуйте контроль доступа, чтобы только авторизованные пользователи могли выполнять или изменять сборки Gradle.



### Regularly update Gradle and plugins

Регулярно обновляйте Gradle и его плагины, чтобы обеспечить устранение уязвимостей в системе безопасности и добавление новых функций. Используйте команду `gradle wrapper`, чтобы убедиться, что все члены команды используют одну и ту же версию Gradle.


