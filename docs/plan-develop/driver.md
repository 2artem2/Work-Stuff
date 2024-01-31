---
layout: default
title:  Driver
parent: Plan & Develop
---

# Драйвер
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---



DevSecOps - это методология, направленная на интеграцию безопасности в жизненный цикл разработки программного обеспечения, а не на рассмотрение ее как отдельного процесса, который прикручивается в конце. Цель заключается в создании безопасного и надежного программного обеспечения, отвечающего потребностям бизнеса, а также в защите конфиденциальных данных и критически важной инфраструктуры. Внедрение DevSecOps связано с несколькими факторами и проблемами, которые описаны ниже.

**Драйверы:**

1. Проблемы безопасности: С ростом частоты и серьезности кибератак безопасность стала главным приоритетом для организаций. DevSecOps позволяет встроить безопасность в процесс разработки программного обеспечения, а не полагаться на специальные меры безопасности.

2. Требования к соответствию: Многие организации подчиняются нормативным требованиям, таким как PCI-DSS, HIPAA и GDPR. DevSecOps может помочь обеспечить соответствие этим нормам, интегрируя безопасность в процесс разработки и обеспечивая видимость уровня безопасности приложения.

3. Гибкость и скорость: DevSecOps может помочь организациям разрабатывать и внедрять программное обеспечение быстрее и с большей оперативностью. Интегрируя систему безопасности в процесс разработки, организации могут сократить время и стоимость устранения проблем и избежать задержек, вызванных проблемами безопасности.

4. Сотрудничество: DevSecOps поощряет сотрудничество между разработчиками, службами безопасности и операционными службами. Благодаря совместной работе эти команды могут создавать более безопасное и надежное программное обеспечение.

**Проблемы:**

1. Культурные барьеры: DevSecOps требует изменения культуры в организации, чтобы разработчики, службы безопасности и операционные группы работали совместно. Это может быть непросто, особенно в организациях с изолированной культурой.

2. Отсутствие навыков: DevSecOps требует целого ряда навыков, включая навыки разработки, безопасности и эксплуатации. Найти людей с такими навыками может быть непросто, особенно на конкурентном рынке труда.

3. Инструментарий и автоматизация: DevSecOps в значительной степени опирается на инструментарий и автоматизацию для интеграции безопасности в процесс разработки. Внедрение и поддержка этих инструментов может быть сложной задачей, особенно для небольших организаций с ограниченными ресурсами.

4. Сложность: DevSecOps может быть сложным, особенно для организаций с большими и сложными приложениями. Интегрировать систему безопасности в процесс разработки без задержек и дополнительных сложностей может быть непросто.


## Стандарт проверки безопасности приложений (ASVS):

Аутентификация, управление сеансами, контроль доступа, обработка вредоносного ввода, кодирование/расшифровка вывода, криптография, обработка ошибок и ведение журналов, защита данных, безопасность связи, настройка Http-безопасности, настройка безопасности, вредоносная, внутренняя безопасность, бизнес-логика, файлы и ресурсы, мобильные, веб-сервисы

### Обзор дизайна 

* Контрольный список соответствия требованиям безопасности 
* Контрольный список требований безопасности (OWASP ASVS) 
* 10 лучших проблем проектирования системы безопасности 
* Проблемы безопасности в предыдущем выпуске 
* Отзывы клиентов или маркетологов о проблемах безопасности 


### Обзор реализации 

* Безопасное кодирование 
* Выбор надежных и безопасных сторонних компонентов 
* Безопасная конфигурация 


### Компоненты сторонних производителей 

* Контрольный список для оценки стороннего ПО: 
* Рекомендуемое стороннее ПО и его использование в проектах: 
* CVE-статус сторонних компонентов: 

### Обзор кода.

* **Статическое тестирование безопасности приложений (SAST)**. 

{: .highlight }
FindSecbugs, Fortify, Coverity, klocwork.

* **Dynamic Application Security Testing (DAST)**

{: .highlight }
OWASP ZAP, BurpSuite

* **Interactive Application Security Testing (IAST)** 

{: .highlight }
CheckMarks Varacode


* **Run-time Application Security Protection(RASP)** 

{: .highlight }
OpenRASP

* **SEI CERT Coding**

{: .highlight }
https://wiki.sei.cmu.edu/confluence/display/seccode/SEI+CERT+Coding+Standards

* **Software Assurance Marketplace (SWAMP)**

{: .highlight }
https://www.mir-swamp.org/

### Environment Hardening 

* Secure configuration baseline 
* Constant monitoring mechanism 

### Constant monitoring mechanism

* **Common vulnerabilities and exposures (CVEs)** 

{: .highlight }
OpenVAS, NMAP 

* **Integrity monitoring**

{: .highlight }
OSSEC

* **Secure configuration compliance**

{: .highlight }
OpenSCAP

* **Sensitive information exposure** 

{: .note }
No specific open source tool in this area. However, we may define specific regular expression patterns


## ENGAGE

https://engage.mitre.org/matrix/



## IACD


### Playbooks

Process Oriented

* Reflects organization's policies and procedures
* List activities that may require human interaction
* Organization-to-organization shareable



#### Playbooks

Process Oriented

* Reflects organization's policies and procedures
* List activities that may require human interaction
* Organization-to-organization shareable



#### Workflows

Technical Steps

* Focused on machine interaction
* Supports tailorable levels of automation
* Machine-to-machine shareable


#### Local Instance

Execution at the System Level

* Activity conducted is tailored to target system
* Describes specific decision logic and thresholds
* Machine-to-machine shareable in organization


### Example Playbook

To represent a general security process in a manner that:
1. Most organizations can associate with a process they are a
performing
2. Can be mapped to governance or regulatory
requirements (e.g., NIST 800-53)
3. Demonstrates a path to automation of the process over time
4. Identifies industry best practices for steps in the process

Playbook Content Types:

1. Initiating Condition
2. Process Steps
3. Best Practices and Local Policies
4. End State
5. Relationship to Governance or Regulatory Requirements



![IACD](../../../assets/images/iacd.png)


Steps to Build a Playbook:


1. Identify the initiating condition.

 Think About: What event or condition is going to start this playbook? This could be a time-based trigger,
the detection of an event, or the decision to act.

2. List all possible actions that could occur in response to this initiating condition.
 Think About: How could I respond to this condition? What steps would I take to mitigate this threat?
Don’t worry about order right now!

3. Iterate through the actions list from Step 2 and categorize the actions based on whether they are required
steps or whether they are optional.
 Think About: Is this step necessary to mitigate or investigate this event, or is it a best practice? Some
best practices have become standardized or widely implemented, while others may be considered extraneous.
It’s OK if it’s unclear whether some actions are required or optional; it’s up to you to categorize accordingly.

4. Use the required steps from Step 3 to build the playbook process steps diagram.
 Think About: Ordering. This is the time to think about the order in which you would perform these
actions.

5. Iterate through the optional actions and decide whether the actions can be grouped by activity or function.
For example: Monitoring, Enrichment, Response, Verification, or Mitigation.

6. Think About: Are there possible actions that can only take place in certain parts of the playbook?
This is how you would group the actions.

7. Modify the playbook process steps diagram from Step 4 to include the points where optional actions
would be selected.







