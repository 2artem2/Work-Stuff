---
layout: default
title: Jenkins
parent: Checklists
---

# Усиление Jenkins для DevSecOps
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Список лучших практик по защите Jenkins для DevSecOps


### Включить защиту


Перейдите в раздел "Управление Jenkins" -> "Настройка глобальной безопасности" и выберите "Включить безопасность".



### Используйте безопасное соединение	


Перейдите в раздел "Управление Jenkins" -> "Настроить глобальную безопасность" и выберите "Требовать безопасные соединения".



### Ограничить доступ к проекту	

Перейдите в конфигурацию проекта -> "Настроить" -> "Включить безопасность на основе проекта".



### Используйте плагины с осторожностью


Устанавливайте только необходимые плагины из надежных источников и регулярно обновляйте их


### Ограничение прав пользователей

Назначьте минимально необходимые разрешения для каждого пользователя или группы



### Безопасное использование учетных данных

Храните учетные данные в хранилище учетных данных Jenkins и используйте их только в случае необходимости.





### Регулярно обновляйте Jenkins	

Постоянно обновляйте Jenkins последними исправлениями и обновлениями безопасности



### Включение регистрации аудита		


Включите регистрацию аудита, чтобы отслеживать и расследовать инциденты безопасности.



### Защита доступа к серверу Jenkins	


Ограничьте доступ к серверу Jenkins, настроив правила брандмауэра и установив VPN-доступ



### Безопасное использование агентов Jenkins	


Используйте безопасные соединения между мастером Jenkins и агентами и ограничьте доступ к агентам



### Безопасное использование инструментов сборки	


Используйте безопасные и обновленные инструменты сборки и избегайте использования системных инструментов или команд непосредственно в сценариях сборки.



### Соблюдайте правила безопасного кодирования	


Следуйте практикам безопасного кодирования, чтобы избежать появления уязвимостей в скриптах сборки или плагинах
