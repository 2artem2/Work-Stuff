---
layout: default
title: Threat Intelligence
parent: Production
---

{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---


# Threat Intelligence
{: .no_toc }

Анализ угроз - это процесс сбора и анализа информации о потенциальных и существующих угрозах кибербезопасности, таких как вредоносное ПО, фишинговые атаки и утечки данных. Цель анализа угроз - предоставить организациям действенные сведения, которые помогут им выявить и смягчить потенциальные риски безопасности до того, как они смогут причинить вред.

В контексте DevSecOps анализ угроз является важным компонентом комплексной стратегии безопасности. Собирая и анализируя информацию о потенциальных угрозах безопасности, организации могут лучше понять риски безопасности, с которыми они сталкиваются, и предпринять шаги по их снижению. Это может включать в себя внедрение средств контроля безопасности и контрмер, таких как брандмауэры, системы обнаружения вторжений и системы управления информацией и событиями безопасности (SIEM), для защиты от известных угроз.

Информация об угрозах также может быть использована для совершенствования других практик DevSecOps, таких как управление уязвимостями и реагирование на инциденты. Выявляя потенциальные уязвимости и угрозы в режиме реального времени, команды безопасности могут оперативно принимать меры по устранению проблем и предотвращению инцидентов безопасности.

К числу ключевых преимуществ анализа угроз в DevSecOps относятся:

1. Улучшенное обнаружение угроз: Анализ угроз предоставляет организациям информацию, необходимую для обнаружения потенциальных угроз безопасности до того, как они смогут причинить вред.

2. Более эффективное принятие решений: Предоставляя действенные сведения, анализ угроз помогает организациям принимать обоснованные решения о состоянии безопасности и реагировании на потенциальные угрозы.

3. Проактивное устранение угроз: Анализ угроз позволяет организациям применять упреждающий подход к снижению угроз, что позволяет им опережать возникающие угрозы и снижать риск быть скомпрометированными.

4. Улучшенное реагирование на инциденты: Анализ угроз может быть использован для повышения эффективности реагирования на инциденты, что позволяет организациям быстро и эффективно реагировать на инциденты безопасности и минимизировать их последствия.



## PCR


* **Приоритет:** Приоритет запроса на сбор информации (PCR) должен определяться с учетом множества факторов и информации. Рекомендуется устанавливать приоритет на основе сочетания нескольких критериев. Одним из важных факторов, который следует учитывать, является клиент, запрашивающий разведданные. Например, если запрос поступил от директора по информационной безопасности (CISO), он будет считаться более значимым по сравнению с запросом от старшего сетевого инженера. Кроме того, на приоритет может влиять конкретная отраслевая вертикаль, на которую ориентирован запрос. Например, если запрос поступает от CTI-аналитика, работающего в банке, менеджер по сбору данных, скорее всего, определит приоритеты сбора информации, исходя из общих угроз, с которыми сталкивается банковская отрасль. Приняв во внимание эти различные факторы, можно присвоить ПКР соответствующий уровень приоритета.



При определении приоритета сбора разведданных необходимо учитывать несколько ключевых факторов. К ним относятся требования заказчика, желаемый результат или итог сбора, временной интервал запроса и возможность выполнения запроса с помощью имеющихся систем сбора. Хотя универсального подхода к определению приоритетов не существует, эти соображения играют решающую роль в определении порядка выполнения запросов. В последующих главах тема приоритетов будет рассмотрена более подробно, особенно в связи с изучением конкретных потребностей организации и ее операций по сбору.






* ** Ключ:** Ключ служит отдельным идентификатором, который может использоваться в сочетании с другими системами для целей ссылки и отслеживания. Он может генерироваться автоматически, как первичный ключ, или сочетаться с уникальными идентификаторами для получения дополнительной информации о типе или приоритете коллекции. Изучив расширенный ключ, например PCR-001-P-BIN-FIN-P1, организация может легко определить характер и значимость коллекции.




![Operationalizing Threat Intelligence A guide to developing and operationalizing cyber threat intelligence programs](../../../assets/images/pcr.png)


## Жизненный цикл операций по сбору информации

Эффективный сбор разведданных требует тщательного планирования с учетом установленных приоритетов сбора, специальных запросов на информацию (RFI) и регулярного управления операциями по сбору. Правильное планирование обеспечивает сбор данных таким образом, чтобы они соответствовали потребностям организации в сборе разведданных.



![Operationalizing Threat Intelligence A guide to developing and operationalizing cyber threat intelligence programs](../../../assets/images/collection.png)


### Pперсонал

Чтобы удовлетворить потребности организации, важно определить приоритетные требования к сбору (PCR) и оценить, есть ли у организации подходящий персонал для их выполнения. Оценка персонала в данном контексте может быть разделена на три категории: технические навыки, владение языком и предметная область знаний (SME). Эти категории помогают менеджеру по сбору информации определить, обладает ли персонал необходимой квалификацией для эффективного сбора информации.




* Техническая дисциплина: Во многих случаях операции по сбору информации могут быть эффективно проведены при наличии соответствующих технических навыков, особенно в случае пассивных и гибридных операций по сбору информации. В этих типах операций для сбора информации в основном используются технические знания, а не активное взаимодействие с сообществами, имеющими проверенный доступ, или разработка источников путем прямого взаимодействия. Главная задача менеджера по сбору - убедиться, что персонал, назначенный на сбор, обладает необходимыми техническими навыками для получения нужных данных.


* Требования к языку: Знание языка может играть важную роль в операциях по сбору информации по нескольким причинам. Во-первых, если собираемая информация написана на определенном языке, наличие человека, способного читать и интерпретировать этот язык, необходимо для извлечения нужных деталей. Кроме того, знание языка становится необходимым при проведении сбора информации в сообществах с проверенным доступом, которые в основном общаются на определенном языке. Кроме того, эти навыки крайне важны при активном взаимодействии с источниками или попытках вербовки людей. Если сбор разведданных требует региональной направленности, то для эффективного проведения операций сотрудникам по сбору информации могут потребоваться носители языка с пониманием культурных и региональных особенностей.






* Область деятельности МСП: В дополнение к техническим и языковым навыкам руководитель сбора информации должен оценить, требуется ли коллекционеру обладать экспертными знаниями (SME) в конкретной области угроз. Обычно люди в индустрии CTI специализируются на таких областях, как программы-вымогатели, банковские трояны, угрозы со стороны национальных государств или современные постоянные угрозы (APT). Если сборщик обладает специальными знаниями в определенной области угроз, рекомендуется назначить его на операцию сбора, а не человека, имеющего лишь общие знания о данном типе угроз. Это гарантирует, что усилия по сбору принесут пользу благодаря глубокому пониманию и знаниям, предоставленным специалистом.





### Процесс

После того как менеджер по сбору информации определил подходящий персонал для операции по сбору, он должен совместно с группой по сбору информации разработать оперативный план. При этом необходимо учитывать несколько ключевых факторов, которые имеют решающее значение для успешного сбора разведданных. Эти факторы будут рассмотрены в следующих разделах.




* OPSEC: мы уже говорили о
Процесс обеспечения безопасности операций (OPSEC) имеет огромное значение и должен быть укоренен в культуре группы. Во время планирования операций менеджер по сбору должен обсудить процессы и процедуры OPSEC с группой по сбору. Это гарантирует, что команда понимает важность OPSEC и не позволит ей успокоиться или почувствовать себя слишком защищенной во время выполнения операции. Включение OPSEC в фазу планирования позволяет группе сохранять бдительность и уделять пристальное внимание защите конфиденциальной информации и поддержанию оперативной безопасности.



* Проанализируйте все текущие разведданные: Во время разработки плана операции руководителю и группе по сбору важно тщательно изучить все разведывательные данные, относящиеся к желаемой информации и ее источнику. Этот обзор дает ценную информацию о процессе сбора, конкретной обстановке, в которой будет проводиться сбор, а также подробности об источнике информации. Проведя этот обзор, команда по сбору данных получает более глубокое понимание требований к сбору и может эффективно адаптировать свой подход для обеспечения успешного сбора данных.



* Учитывайте разветвления или продолжения операций: При планировании операций по сбору очень важно учитывать историю предыдущих сборов данных из конкретного источника. Эта история может дать ценные сведения об операциях группы сбора и истории, которую она рассказывает. Например, она может выявить такие закономерности, как неоднократное использование определенных диапазонов IP-адресов или VPN, что может свидетельствовать об отслеживании пользовательской информации. В более сложных сценариях, таких как сбор информации на темных рынках или хакерских форумах, группа сбора должна тщательно оценить свою историю в этих местах. Они должны учитывать такие факторы, как существующие персоны, любые инциденты, которые могли скомпрометировать их личности, и возможность организации нескольких операций по сбору. Понимание истории сбора информации из источника очень важно для эффективного планирования операций.






### Инструменты и технологии

Обеспечив наличие подходящего персонала и проведя тщательное планирование, менеджер по сбору должен сосредоточиться на технологиях и инфраструктуре, необходимых для реализации операционного плана. Это включает в себя оценку необходимых инструментов и систем сбора. Под инструментами сбора понимается конкретное программное или аппаратное обеспечение, используемое для сбора разведданных, в то время как системы сбора включают в себя более широкую инфраструктуру, необходимую для обеспечения оперативной безопасности (OPSEC) и требований к сбору. Руководителю сбора необходимо оценить, имеет ли группа доступ к соответствующим технологиям и инфраструктуре для эффективного осуществления деятельности по сбору.








## Lockheed's Martin Cyber Kill Chain

![Lockheed's Martin Cyber Kill Chain](../../../assets/images/lock_kill.png)

### Разведка:

* Пример: Атакующий собирает информацию о целевой организации, используя общедоступные источники, социальные сети или другие методы разведки.

* Шпаргалка по командам и инструментам:
	* WHOIS lookup: `whois <target>`
	* DNS enumeration: `nslookup <target>`
	* Google dorking: `site:<target>`

### Оружие:

* Пример: Атакующий создает или получает вредоносную полезную нагрузку, например вредоносную программу или эксплойт, для доставки цели.

* Шпаргалка по командам и инструментам:
	* Metasploit Framework: `msfvenom -p <payload> -f <format> -o <output>`.
	* Veil-Evasion: `veil-evasion`.

### Доставка:

* Пример: Злоумышленник доставляет полезную нагрузку с помощью различных методов, таких как вложения в электронную почту, взломанные веб-сайты или социальная инженерия.

* Команды и инструменты "Шпаргалки":
	* Генерация фишинговых писем: GoPhish, SET
	* Хостинг вредоносных веб-сайтов: Apache, Nginx
	* Наборы эксплойтов: Blackhole, Angler

### Эксплуатация:

* Пример: Злоумышленник использует уязвимости в системе или приложениях объекта для получения несанкционированного доступа.

* Шпаргалки по командам и инструментам:
	* Фреймворки для эксплойтов: Metasploit, ExploitDB
	* Разработка эксплойтов: Python, Ruby, C/C++
	* Сканеры веб-приложений: Nessus, Nikto

### Установка:

* Пример: Злоумышленник устанавливает бэкдоры, средства удаленного доступа или другое вредоносное ПО для обеспечения устойчивости и сохранения контроля над взломанной системой.

* Команды и инструменты из шпаргалки:
	* Средства удаленного администрирования: Netcat, TeamViewer
	* Трояны удаленного доступа (RAT): DarkComet, Poison Ivy
	* Вредоносные программы без файлов: PowerShell, WMI

### Управление и контроль (C2):

* Пример: Злоумышленник устанавливает каналы связи со взломанной системой для удаленного контроля и управления атакой.

* Шпаргалка по командам и инструментам:
	* C2-фреймворки: Cobalt Strike, Metasploit.
	* Зашифрованная связь: TOR, SSL/TLS
	* Связь на основе DNS: Dnsmasq, Dnscat2

### Действия по целям:

* Пример: Атакующий достигает намеченных целей, которые могут включать кражу данных, повышение привилегий, дальнейшую компрометацию сети или нарушение работы служб.

* Команды и инструменты из шпаргалки:
	* Эксфильтрация данных: FTP, SCP, стеганография
	* Повышение привилегий: sudo, PowerSploit
	* Сетевое распространение: EternalBlue, WannaCry

### Боковое перемещение:

* Пример: Атакующий перемещается по сети в поисках дополнительных целей или систем для компрометации.

* Команды и инструменты из шпаргалки:
	* Сканирование сети: Nmap, Masscan
	* Кража учетных данных: Mimikatz, Responder
	* Pass-the-Hash: Psexec, PsExecWrapper




## Матрица угроз DevOps

![Microsoft DevOps Threat](../../../assets/images/microsoft_devops_threat.png)

Матрица угроз DevOps - это комплексная структура или ресурс, который определяет и классифицирует потенциальные угрозы безопасности и риски, связанные с внедрением практики DevOps. Ее цель - дать организациям представление о проблемах безопасности, с которыми они могут столкнуться при внедрении подхода DevOps, и предложить рекомендации по снижению этих рисков.

Упомянутый вами блог Microsoft Security Blog, вероятно, содержит подробную информацию об их матрице угроз DevOps. Она может охватывать различные категории угроз, такие как:

* Инсайдерские угрозы: Сюда входят потенциальные риски, возникающие из-за сотрудников или лиц с авторизованным доступом к системам, данным или инфраструктуре.

* Внешние атаки: Это угрозы, исходящие от внешних субъектов, таких как хакеры, которые пытаются использовать уязвимости в среде DevOps.

* Потеря и утечка данных: В эту категорию входят риски, связанные с несанкционированным раскрытием или потерей конфиденциальной информации в процессе работы DevOps.

* Атаки на цепочки поставок: Эти угрозы связаны с компрометацией цепочки поставок программного обеспечения, направленной на сторонние библиотеки, зависимости или процессы сборки.

* Уязвимости инфраструктуры: В данном случае речь идет о слабых местах в инфраструктурных компонентах среды DevOps, таких как неправильная конфигурация или небезопасные облачные сервисы.

* Соответствие нормативным требованиям и нормативные риски: Практика DevOps должна соответствовать отраслевым стандартам и нормативным требованиям. Несоблюдение этих требований может привести к юридическим и финансовым последствиям.

Матрица угроз DevOps, вероятно, предоставит организациям действенные рекомендации, лучшие практики и средства контроля безопасности, которые можно внедрить на различных этапах жизненного цикла DevOps. Сюда могут входить методы безопасного кодирования, непрерывный мониторинг, сканирование уязвимостей, контроль доступа и процедуры реагирования на инциденты.


### Первоначальный доступ

В контексте матрицы угроз DevOps "Первоначальный доступ" относится к категории угроз, которые сосредоточены на несанкционированных точках входа или механизмах, с помощью которых злоумышленник получает первоначальный доступ к системе или сети. Она предполагает использование уязвимостей или слабых мест в инфраструктуре, приложениях или процессах DevOps для создания плацдарма для дальнейшей вредоносной деятельности.


#### Аутентификация в SCM

![](../../../assets/images/scm.png)

Аутентификация SCM - это процесс проверки подлинности и доступа к системе управления исходным кодом (SCM) организации. Обычно для этого используются такие методы аутентификации, как персональные маркеры доступа (PAT), ключи SSH или другие разрешенные учетные данные. Однако злоумышленники могут попытаться использовать этот процесс аутентификации, получая несанкционированный доступ к SCM с помощью таких методов, как фишинговые атаки. Это может представлять значительную угрозу для исходного кода и конфиденциальной информации организации. Чтобы снизить этот риск, очень важно знать о возможных атаках и применять надежные меры безопасности.




#### Аутентификация сервисов CI/CD

![](../../../assets/images/cicd-initial.drawio.png)


Аутентификация сервисов CI/CD - это процесс аутентификации и доступа к сервису непрерывной интеграции/непрерывного развертывания (CI/CD), используемому организацией для автоматизации конвейеров доставки программного обеспечения. Злоумышленники могут попытаться использовать уязвимости в процессе аутентификации для получения несанкционированного доступа к сервису CI/CD, что может привести к потенциальному компромиссу в среде DevOps организации. Чтобы снизить этот риск, важно использовать надежные методы аутентификации и применять меры безопасности для защиты CI/CD-сервиса от несанкционированного доступа.





#### Публичные репозитории организации

![](../../../assets/images/github.drawio.png)


Доступ к публичным репозиториям организации с возможностями CI/CD может представлять угрозу безопасности, если он не защищен должным образом. Злоумышленники могут попытаться получить несанкционированный доступ к этим репозиториям и использовать их возможности CI/CD для выполнения вредоносного кода или нарушения работы конвейеров организации. Чтобы снизить этот риск, организациям следует внедрить строгий контроль доступа, отслеживать активность в репозиториях и обеспечивать безопасные конфигурации CI/CD.




#### Компрометация конечных точек


![](../../../assets/images/endpoint.drawio.png)


Компрометация конечной точки - это сценарий, при котором злоумышленник получает доступ к ресурсам организации, компрометируя рабочую станцию или конечное устройство разработчика. Если конечная точка скомпрометирована, злоумышленник может использовать скомпрометированную рабочую станцию для получения несанкционированного доступа к управлению исходным кодом (SCM), реестру или другим критическим ресурсам организации. Чтобы снизить этот риск, организациям следует внедрить надежные меры безопасности конечных точек и следовать лучшим практикам защиты рабочих станций разработчиков.





#### Настроенные вебхуки

![](../../../assets/images/webhook.drawio.png)


Настроенные веб-хуки могут стать потенциальным риском безопасности, если их не защитить должным образом. Злоумышленники могут использовать эти веб-хуки для получения первоначального доступа к сети организации. Запуская запросы через систему управления исходным кодом (SCM), злоумышленники могут получить несанкционированный доступ к службам, которые не должны быть открыты для публичного доступа или могут работать с устаревшими и уязвимыми версиями программного обеспечения в частной сети организации. Чтобы снизить этот риск, организациям следует внедрить безопасные конфигурации веб-хуков, отслеживать активность веб-хуков и применять необходимые средства контроля доступа.






### Исполнение


Тактика исполнения в матрице угроз DevOps относится к методам, используемым злоумышленниками для получения доступа к ресурсам пайплайна, включая сам пайплайн или ресурсы развертывания. Злоумышленники могут использовать уязвимости или применять различные техники для получения несанкционированного контроля над этими ресурсами. Понимание этих методов и применение соответствующих мер безопасности имеет решающее значение для снижения риска несанкционированного выполнения и сохранения целостности пайплайна DevOps.



#### Выполнение зараженного пайплайна (PPE)

![](../../../assets/images/ppe.png)


Заражённый пайплайн (Poisoned pipeline execution, PPE) - это техника, используемая злоумышленниками для внедрения вредоносного кода в репозиторий организации, что позволяет им выполнять несанкционированные действия в системе CI/CD репозитория. Эта техника представляет собой серьезную угрозу, поскольку может привести к выполнению вредоносного кода в процессе CI/CD, нарушая целостность пайплайна и потенциально позволяя получить дальнейший несанкционированный доступ. Понимание и снижение рисков, связанных с выполнением зараженных пайплайнов, очень важно для поддержания безопасности системы CI/CD.





##### Прямое выполнение загрязненного пайплайна (d-PPE)


Прямое выполнение отравленного пайплайна (d-PPE) - это техника, используемая злоумышленниками для прямого изменения конфигурационного файла в хранилище. Внедрив вредоносные команды в файл конфигурации, злоумышленник может выполнить их во время работы пайплайна, что может привести к нарушению целостности пайплайна и связанных с ним ресурсов. Снижение риска d-PPE требует внедрения безопасных методов, обеспечения строгого контроля доступа и тщательной проверки конфигурационных файлов.





##### Косвенное выполнение конвейера (i-PPE)


Косвенное выполнение зараженного пайплайна (i-PPE) - это техника, используемая злоумышленниками, когда они не могут напрямую изменять конфигурационные файлы или когда эти изменения не учитываются при выполнении пайплайна. В таких случаях злоумышленники нацеливаются на скрипты, используемые пайплайном, такие как make-файлы, тестовые скрипты, скрипты сборки или другие подобные файлы, чтобы внедрить в них вредоносный код. Заразив эти скрипты, злоумышленник может выполнить несанкционированный код во время работы пайплайна, что может привести к компрометации пайплайна и связанных с ним ресурсов. Чтобы снизить риск i-PPE, важно внедрять безопасные методы, проводить тщательный анализ кода и обеспечивать целостность сценариев пайплайнов.




##### Публичный PPE


Публичное выполнение зараженного пайплайна (Public PPE) относится к сценариям, в которых пайплайн запускается проектом с открытым исходным кодом. В таких случаях злоумышленники могут эксплуатировать пайплайн, применяя такие техники, как прямое выполнение зараженного пайплайна (d-PPE) или косвенное выполнение зараженного пайплайна (i-PPE) в публичном репозитории. Заразив пайплайн в проекте с открытым исходным кодом, злоумышленник может выполнить несанкционированный код во время работы пайплайна, что может нарушить целостность пайплайна и ресурсов, с которыми он взаимодействует. Чтобы снизить риск публичного PPE, необходимо внедрять безопасные методы, проводить тщательный анализ кода и контролировать выполнение пайплайна.





#### Вскрытие зависимостей

![](../../../assets/images/dependency.drawio.png)


Подделка зависимостей - это техника, используемая злоумышленниками для выполнения вредоносного кода в DevOps или производственной среде путем внедрения вредоносного кода в зависимости репозитория. Когда эти зависимости загружаются и интегрируются в систему, вредоносный код начинает выполняться, что может привести к несанкционированному доступу или нарушению целостности среды. Для предотвращения и снижения риска подделки зависимостей необходимо применять безопасные методы, регулярно проводить аудит зависимостей и обеспечивать их целостность.






##### Публичная путаница зависимостей

Публичная путаница зависимостей - это техника, используемая злоумышленниками, когда они публикуют в публичных реестрах вредоносные пакеты с теми же именами, что и частные пакеты. Когда механизмы контроля пакетов ищут пакеты, они часто отдают приоритет публичным реестрам, что позволяет загрузить вредоносный пакет вместо предполагаемого частного пакета. Эта техника может привести к выполнению вредоносного кода в среде DevOps или в производственной среде. Для предотвращения и снижения риска путаницы публичных зависимостей необходимо применять безопасные методы, проверять источники пакетов и отдавать предпочтение доверенным реестрам.




##### Перехват публичных пакетов ("repo-jacking").

Перехват публичного пакета, также известный как "repo-jacking", подразумевает получение злоумышленниками контроля над публичным пакетом путем компрометации учетной записи сопровождающего. Эта техника может применяться, когда злоумышленники используют уязвимости или слабые места в учетных записях сопровождающих пакетов, например, при использовании функции переименования пользователей на GitHub. Получив контроль над пакетом, злоумышленники могут изменить его код, внедрить вредоносный код или перенаправить пользователей на вредоносные ресурсы. Для снижения риска захвата публичных пакетов необходимо применять меры безопасности, регулярно контролировать репозитории пакетов и обеспечивать целостность учетных записей сопровождающих.




##### Typosquatting

Typosquatting - это техника, используемая злоумышленниками, когда они публикуют вредоносные пакеты с именами, похожими на известные публичные пакеты. Создавая такие обманчивые имена пакетов, злоумышленники стремятся ввести пользователей в заблуждение, чтобы они случайно загрузили вредоносные пакеты вместо тех, которые были предназначены для них. Эта техника может привести к выполнению несанкционированного или вредоносного кода в среде DevOps или производственной среде. Для предотвращения и снижения риска опечаток необходимо применять безопасные методы, проверять источники пакетов и информировать пользователей о потенциальных рисках.





#### Компрометация ресурсов DevOps

![](../../../assets/images/resources.drawio.png)



Компрометация ресурсов DevOps относится к сценариям, в которых злоумышленники атакуют вычислительные ресурсы, используемые для выполнения CI/CD-агентов и другого программного обеспечения в рамках пайплайна. Используя уязвимости в операционной системе, коде агентов или другом программном обеспечении, установленном на виртуальных машинах (ВМ) или сетевых устройствах, злоумышленники могут получить несанкционированный доступ к пайплайну. Такая компрометация может привести к выполнению несанкционированного кода, краже данных или нарушению процесса CI/CD. Чтобы снизить риск компрометации ресурсов DevOps, крайне важно применять меры безопасности, регулярно обновлять и исправлять программное обеспечение, а также отслеживать инфраструктуру на предмет подозрительной активности.





#### Control of common registry

![](../../../assets/images/registry.drawio.png)



Control of a common registry refers to a situation where an attacker gains control over a registry used by the organization, allowing them to introduce and execute malicious images or packages within the CI/CD pipeline or production environment. This compromise can lead to the execution of unauthorized or malicious code, data breaches, or disruption of the CI/CD process. Protecting against the control of a common registry requires implementing robust security measures, controlling access to the registry, and monitoring for any suspicious or unauthorized activities.







### Persistence

The persistency tactic in the context of DevOps threat matrix refers to techniques employed by attackers to maintain access to a victim's environment even after initial compromise. These techniques allow attackers to persistently control and access the compromised systems, potentially leading to further unauthorized activities, data breaches, or system disruptions. Mitigating the risk of persistency requires implementing strong security practices, conducting regular system audits, and promptly addressing any identified vulnerabilities or unauthorized access.




#### Changes in repository

![](../../../assets/images/per-reg.drawio.png)


Changes in repository refer to techniques where adversaries exploit the automatic tokens within the CI/CD pipeline to access and push code changes to the repository. By leveraging these tokens, which often have sufficient permissions, attackers can achieve persistency within the environment. This persistence can enable unauthorized code modifications, data exfiltration, or further exploitation of the organization's systems. Preventing and mitigating the risk of changes in the repository requires implementing secure practices, controlling access to tokens, and monitoring repository activities for any suspicious or unauthorized changes.

* Change/add scripts in code – we can change some of the initialization scripts/add new scripts, so they download a backdoor/starter for the attacker, so each time the pipeline is executing these scripts, the attacker’s code will be executed too.

* Change the pipeline configuration – we can add new steps in the pipeline to download an attacker-controlled script to the pipeline before continuing with the build process.

* Change the configuration for dependencies locations – to use attacker-controlled packages.


##### Inject in Artifacts

![](../../../assets/images/per-arti.drawio.png)


Injecting code into artifacts involves exploiting the functionality of Continuous Integration (CI) environments that allow the creation and sharing of artifacts between pipeline executions. Attackers can manipulate these artifacts to inject malicious code or files, which can lead to unauthorized code execution or compromise of the CI/CD pipeline. Preventing and mitigating the risk of artifact injection requires implementing security measures, validating artifacts, and monitoring for any suspicious or unauthorized changes.






##### Modify images in registry

![](../../../assets/images/per-img.drawio.png)



Modifying images in the registry refers to a technique where an attacker gains access to the image registry used by CI/CD pipelines and manipulates the images stored in the registry. By modifying or planting malicious images, the attacker can ensure that these images are executed by the user's containers, leading to the execution of unauthorized or malicious code within the production environment. Preventing and mitigating the risk of image modification in the registry requires implementing strong security measures, controlling access to the registry, and monitoring for any unauthorized changes.





##### Create service credentials

![](../../../assets/images/per-service.drawio.png)


Creating service credentials in the context of DevOps refers to the process of generating and managing authentication credentials for services or applications used within the CI/CD pipeline or infrastructure. Service credentials provide secure access to various resources, such as cloud platforms, databases, or external APIs, and help establish trust and authorization between different components of the DevOps environment. Properly managing service credentials is crucial for maintaining the security and integrity of the DevOps pipeline and ensuring authorized access to sensitive resources.






### Privilege escalation

Privilege escalation techniques in the context of DevOps refer to the methods used by an attacker to elevate their privileges within a victim's environment. By gaining higher privileges, the attacker can access more sensitive resources, manipulate configurations, and potentially compromise the entire DevOps infrastructure. Understanding and mitigating privilege escalation risks is crucial to maintaining the security and integrity of the DevOps environment.




#### Secrets in private repositories

![](../../../assets/images/priv-pro.drawio.png)


The presence of secrets in private repositories poses a significant security risk within the DevOps environment. Attackers who have gained initial access can leverage this access to scan private repositories in search of hidden secrets. Private repositories are typically considered more secure as they are inaccessible from outside the organization. However, if sensitive information such as API keys, passwords, or cryptographic keys are mistakenly committed or stored within these repositories, they can be exposed to unauthorized individuals. Detecting and mitigating the presence of secrets in private repositories is essential to maintain the confidentiality and integrity of the organization's assets.





##### Commit/push to protected branches

![](../../../assets/images/priv-key.drawio.png)

Committing or pushing code to protected branches in a repository can pose a significant security risk in the DevOps environment. If the pipeline has access to the repository and the repository's access controls are permissive, it may allow an attacker to bypass normal code review and approval processes and inject malicious code directly into important branches without the intervention of the development team. This can lead to unauthorized code execution, compromising the integrity and security of the application or system. Implementing proper access controls and review processes is crucial to mitigate the risk of unauthorized code changes in protected branches.






##### Certificates and identities from metadata services

![](../../../assets/images/priv-cert.drawio.png)



In cloud-hosted pipelines, attackers may exploit the access they already have to the environment to gain unauthorized access to certificates and identities stored in metadata services. These services, often provided by cloud platforms, store sensitive information such as certificates, authentication tokens, and identity-related data. Extracting such information allows the attacker to assume the privileges associated with those certificates or identities, potentially compromising the security and confidentiality of the DevOps environment. Protecting and securing certificates and identities from metadata services is crucial to prevent unauthorized access and maintain the integrity of the system.






### Credential access



Credential access techniques refer to the methods used by attackers to steal credentials within the DevOps environment. By obtaining valid credentials, attackers can gain unauthorized access to critical systems, services, or resources. It is crucial to protect credentials and implement measures to prevent their unauthorized access or theft. Understanding and mitigating credential access risks is essential to maintain the security and integrity of the DevOps environment.




#### User credentials

![](../../../assets/images/cred-key.drawio.png)


User credentials are often required in CI pipelines to access external services such as databases, APIs, or other resources. However, if not properly secured, these credentials can become a target for attackers. They may try to gain access to the pipeline and extract the credentials to gain unauthorized access to external services. Protecting user credentials is crucial to prevent unauthorized access and maintain the security of the DevOps environment.





##### Service credentials

![](../../../assets/images/cred-serv.drawio.png)

Service credentials, such as service principal names (SPN) and shared access signature (SAS) tokens, are commonly used in DevOps environments to authenticate and authorize access to various services and resources. However, if these credentials are compromised, an attacker can gain unauthorized access to other services directly from the pipeline. Protecting service credentials is essential to prevent unauthorized access and maintain the security of the DevOps environment.








### Lateral movement


The lateral movement tactic in CI/CD environments refers to the techniques used by attackers to move through different resources within the DevOps pipeline. Attackers aim to gain access to deployment resources, build artifacts, registries, or other targets to expand their reach and carry out malicious activities. Detecting and preventing lateral movement is crucial to maintain the security and integrity of the CI/CD environment.




#### Compromise build artifacts

![](../../../assets/images/arti.drawio.png)

Compromising build artifacts is a supply chain attack where an attacker gains control over the CI pipelines and manipulates the build artifacts. By injecting malicious code into the building materials before the build process is completed, the attacker can introduce malicious functionality into the final build artifacts. Protecting build artifacts is essential to prevent the deployment of compromised or malicious software.





##### Registry injection

![](../../../assets/images/regi.drawio.png)

Registry injection is a technique where an attacker infects the registry used for storing build artifacts in a CI/CD pipeline. By injecting malicious images into the registry, the attacker aims to have these images downloaded and executed by containers that rely on the infected registry. Preventing registry injection is crucial to ensure the integrity and security of the build artifacts used in the CI/CD process.






##### Spread to deployment resources

![](../../../assets/images/depi.drawio.png)

Spreading to deployment resources refers to the scenario where an attacker gains access to the deployment resources within a CI/CD pipeline. By leveraging the access granted to the pipeline, the attacker can propagate their presence to the deployment environment, leading to potential code execution, data exfiltration, and other malicious activities. Preventing the spread to deployment resources is crucial to maintain the security and integrity of the deployment environment.






### Defense evasion

Defense evasion techniques are employed by attackers to bypass or evade the security measures and defenses implemented in a DevOps environment. By evading detection and mitigation mechanisms, attackers can continue their attacks undetected and maintain persistence within the environment. Understanding and mitigating these evasion techniques is crucial to ensure the security and resilience of a DevOps environment.




#### Service logs manipulation

![](../../../assets/images/monitoring.drawio.png)

Service logs manipulation is a technique where an attacker, who has gained access to the environment, modifies the logs generated by various services. By tampering with the logs, the attacker aims to hide their activities and prevent defenders from detecting their presence or identifying the attacks they have executed. Detecting and preventing service logs manipulation is crucial for maintaining the integrity and reliability of log data for security analysis.





##### Compilation manipulation

![](../../../assets/images/change.drawio.png)

Compilation manipulation is a technique used by attackers to inject malicious code into the compilation process, which can result in the inclusion of backdoors or vulnerabilities in the final software build. By tampering with the compilation process, the attacker aims to evade detection and introduce malicious functionality into the software without leaving obvious traces in the source code or version control system.







##### Reconfigure branch protections

![](../../../assets/images/unprotected.drawio.png)


Reconfiguring branch protections is a technique where an attacker with administrative permissions modifies the configuration settings of branch protection tools. By altering these settings, the attacker can bypass the controls and introduce code into a branch without the need for any user intervention or approval. This can enable the attacker to inject malicious code into the codebase and potentially compromise the integrity of the repository.






### Impact

The impact tactic refers to techniques used by attackers to exploit access to CI/CD resources for malicious purposes. Unlike other tactics, these techniques are not intended to be stealthy or covert, but rather to cause immediate and noticeable damage or disruption to the organization's CI/CD pipelines and resources. These techniques can have a significant impact on the availability, integrity, and confidentiality of the software development and deployment processes.




#### DDoS

![](../../../assets/images/dos.drawio.png)

DDoS (Distributed Denial of Service) is a type of attack where an adversary overwhelms a target system or network with a flood of traffic from multiple sources, causing service disruptions or outages. In a CI/CD environment, an attacker with access to compute resources can misuse them to launch DDoS attacks against external targets.




##### Cryptocurrency mining

![](../../../assets/images/crypto.drawio.png)


Cryptocurrency mining is the process of using computational resources to solve complex mathematical problems and earn cryptocurrency rewards. In a compromised CI/CD environment, an attacker may utilize the compute resources for unauthorized cryptocurrency mining, consuming system resources and potentially causing performance degradation.


##### Local DoS

![](../../../assets/images/localdos.drawio.png)


Local Denial of Service (DoS) attacks are performed by an attacker who has gained access to the CI pipelines. The attacker uses the pipelines to launch DoS attacks against the organization's own infrastructure or services, causing disruptions or overloading the virtual machines (VMs) used in the CI/CD environment.




##### Resource deletion

![](../../../assets/images/res-del.drawio.png)


Resource deletion is a technique used by attackers who have gained access to CI/CD resources to cause denial of service by permanently deleting critical resources, such as cloud resources or repositories. By deleting these resources, the attacker disrupts the organization's operations and prevents normal functioning of the CI/CD environment.










### Exfiltration

The exfiltration tactic involves various techniques used by attackers to extract sensitive data from a victim's environment in a CI/CD context. These techniques aim to bypass security controls and transfer data outside the organization's network or infrastructure.




#### Clone private repositories

![](../../../assets/images/ex-pro.drawio.png)


In this scenario, the attacker leverages their access to the CI pipelines to clone private repositories, giving them access to sensitive code and potentially valuable intellectual property. They exploit the permissions and tokens available within the CI environment, such as GITHUB_TOKEN in GitHub, to clone private repositories.




##### Pipeline logs

![](../../../assets/images/ex-pip.drawio.png)



In this scenario, the attacker exploits their access to the CI/CD pipelines to access and view the pipeline execution logs. These logs often contain valuable information about the build process, deployment details, and potentially sensitive data such as credentials to services and user accounts.




##### Exfiltrate data from production resources

![](../../../assets/images/ex-res.drawio.png)


In this scenario, the attacker exploits their access to the CI/CD pipelines, which also have access to production resources. This allows the attacker to exfiltrate sensitive data from the production environment using the pipeline as a means of transportation.



## Kubernetes Threat Matrix

![Microsoft Kubernetes Threat Threat](../../../assets/images/k8s-matrix.png)


The Threat Matrix highlights various attack techniques, including both known and hypothetical scenarios, that could be exploited by adversaries targeting Kubernetes environments. It categorizes these techniques into different stages of the attack lifecycle, such as initial access, privilege escalation, lateral movement, persistence, and exfiltration.





### Initial access

As organizations embrace containerized environments like Kubernetes, it becomes essential to understand the potential vulnerabilities and attack vectors that adversaries may exploit. The initial access tactic poses a significant threat, serving as the entry point for unauthorized actors into Kubernetes clusters. In this article, we will explore some common techniques used to gain initial access and discuss proactive measures to secure your Kubernetes environment.



#### Using cloud credentials


In cloud-based Kubernetes deployments, compromised cloud credentials can spell disaster. Attackers who gain access to cloud account credentials can infiltrate the cluster's management layer, potentially leading to complete cluster takeover. It is crucial to implement robust cloud security practices, such as strong access controls and multi-factor authentication, to safeguard against unauthorized access to cloud credentials.



#### Compromised images in registry



Running compromised container images within a cluster can introduce significant risks. Attackers with access to a private registry can inject their own compromised images, which can then be inadvertently pulled by users. Additionally, using untrusted images from public registries without proper validation can expose the cluster to malicious content. Employing image scanning and verifying the trustworthiness of container images can help mitigate this risk.




#### Kubeconfig file



The kubeconfig file, which contains cluster details and credentials, is used by Kubernetes clients like kubectl. If an attacker gains access to this file, they can exploit it to gain unauthorized access to the Kubernetes clusters. Securing the kubeconfig file through secure distribution channels, enforcing access controls, and employing secure client environments are essential steps to mitigate this risk.




#### Vulnerable application



Running a vulnerable application within a cluster can open the door to initial access. Exploiting remote code execution vulnerabilities in containers can allow attackers to execute arbitrary code. If a service account is mounted to the compromised container, the attacker can use its credentials to send requests to the Kubernetes API server. Regularly patching and updating container images, along with implementing strong network segmentation, are crucial to mitigating this risk.





#### Exposed dashboard



The Kubernetes dashboard, when exposed externally without proper authentication and access controls, becomes a potential entry point for unauthorized access. Attackers can exploit an exposed dashboard to gain remote management capabilities over the cluster. It is essential to restrict access to the dashboard, enable authentication, and ensure it is accessible only through secure connections.




### Execution

Once attackers gain initial access to a Kubernetes cluster, the execution tactic becomes their next focus. By leveraging various techniques, attackers attempt to run their malicious code within the cluster, potentially causing widespread damage. In this article, we will explore common execution techniques in Kubernetes and discuss key strategies to mitigate the associated risks.




#### Exec into container:



Attackers with sufficient permissions can exploit the "exec" command ("kubectl exec") to run malicious commands inside containers within the cluster. By using legitimate images, such as popular OS images, as a backdoor container, attackers can remotely execute their malicious code through "kubectl exec." Limiting permissions and enforcing strict access controls will help prevent unauthorized execution within containers.



#### New container:




Attackers with permissions to deploy pods or controllers, like DaemonSets, ReplicaSets, or Deployments, may attempt to create new resources within the cluster for running their code. It is crucial to regularly audit and review access controls, ensuring that only authorized entities can create and deploy containers. Monitoring the creation of new resources and implementing least privilege principles will limit unauthorized code execution.





#### Application exploit:




Exploiting vulnerabilities in applications deployed within the cluster presents an opportunity for attackers to execute their code. Vulnerabilities that allow remote code execution or enable unauthorized access to resources can be leveraged. Mounting service accounts to containers, which is the default behavior in Kubernetes, may grant attackers the ability to send requests to the API server using compromised service account credentials. Regular patching and vulnerability management are crucial to mitigating this risk.





#### SSH server running inside container:




In some cases, attackers may discover containers running SSH servers. If attackers acquire valid credentials, either through brute-force attempts or phishing, they can exploit these SSH servers to gain remote access to the container. To mitigate this risk, it is essential to employ strong authentication mechanisms, enforce secure credential management practices, and regularly audit containers for unauthorized SSH servers.





### Persistence

In the context of Kubernetes security, persistence refers to the techniques employed by attackers to maintain access to a cluster even after their initial entry point has been compromised. By understanding and addressing the persistence tactics used by adversaries, organizations can strengthen their security posture and protect their Kubernetes environments. In this article, we will explore common persistence techniques in Kubernetes and discuss strategies to mitigate these risks.





#### Backdoor container:




One method attackers employ to establish persistence is by running malicious code within a container in the cluster. By leveraging Kubernetes controllers like DaemonSets or Deployments, attackers can ensure that a specific number of containers constantly run on one or more nodes in the cluster. To counter this, regular monitoring of controller configurations and thorough auditing of container images can help detect and remove unauthorized backdoor containers.





#### Writable hostPath mount:





The hostPath volume allows mounting a directory or file from the host to a container. Attackers with permissions to create containers within the cluster can exploit this feature by creating a container with a writable hostPath volume. This provides them with persistence on the underlying host and potential avenues for unauthorized access. Implementing strict access controls and regular auditing of container configurations can help identify and mitigate this risk.






#### Kubernetes CronJob:





Kubernetes CronJob is a scheduling mechanism used to run Jobs at specified intervals. Attackers may leverage Kubernetes CronJob functionality to schedule the execution of malicious code as a container within the cluster. This allows them to maintain persistence by regularly running their code. Monitoring and reviewing CronJob configurations, as well as conducting periodic vulnerability scans, are crucial in identifying and addressing any unauthorized or suspicious CronJobs.





### Privilege escalation


Privilege escalation is a critical tactic employed by attackers to gain higher privileges within a Kubernetes environment. By obtaining elevated access, attackers can potentially compromise the entire cluster, breach cloud resources, and disrupt critical operations. Understanding common privilege escalation techniques is crucial for implementing effective security measures. In this article, we will explore common privilege escalation techniques in Kubernetes and discuss strategies to mitigate these risks.






#### Privileged container


A privileged container possesses all the capabilities of the host machine, allowing unrestricted actions within the cluster. Attackers who gain access to a privileged container, or have permissions to create one, can exploit the host's resources. It is essential to enforce strict container security policies, limit the creation of privileged containers, and regularly monitor for unauthorized access or configuration changes.






#### Cluster-admin binding


Role-based access control (RBAC) is a fundamental security feature in Kubernetes, controlling the actions of different identities within the cluster. Cluster-admin is a built-in high-privileged role in Kubernetes. Attackers with permissions to create bindings and cluster-bindings can create a binding to the cluster-admin ClusterRole or other high-privileged roles. Implementing least privilege principles, regularly reviewing RBAC configurations, and conducting frequent audits are vital for preventing unauthorized privilege escalation.




#### hostPath mount


Attackers can leverage the hostPath volume mount to gain access to the underlying host, breaking out of the container's isolated environment. This allows them to escalate privileges from the container to the host. Implementing strict access controls, conducting regular vulnerability scans, and monitoring for suspicious hostPath mount configurations are essential for mitigating this risk.





#### Accessing cloud resources:



In cloud-based Kubernetes deployments, attackers may leverage their access to a single container to gain unauthorized access to other cloud resources outside the cluster. For instance, in Azure Kubernetes Service (AKS), each node contains a service principal credential used for managing Azure resources. Attackers who gain access to this credential file can exploit it to access or modify cloud resources. Strictly managing access to service principal credentials, encrypting sensitive files, and regularly rotating credentials are critical mitigation steps.







### Defense evasion


Defense evasion techniques are employed by attackers to evade detection and conceal their activities within Kubernetes environments. By actively evading security measures, attackers can prolong their presence, increase the likelihood of successful attacks, and bypass traditional security controls. Understanding common defense evasion techniques is crucial for organizations to enhance threat detection capabilities and bolster overall Kubernetes security. In this article, we will explore common defense evasion tactics and discuss strategies to mitigate these risks effectively.




#### Clear container logs:


Attackers may attempt to delete application or operating system logs on compromised containers to conceal their malicious activities. Organizations should implement robust log management practices, including centralizing logs and establishing secure backup mechanisms. Regularly monitoring log files for suspicious activities and implementing access controls to prevent unauthorized log modifications are vital to maintain visibility into container activities.




#### Delete Kubernetes events:


Kubernetes events play a critical role in logging state changes and failures within the cluster. Attackers may seek to delete Kubernetes events to avoid detection of their activities. Organizations should ensure proper event logging and implement log integrity checks to detect any tampering or deletion of events. Retaining logs in a secure and immutable manner can aid in the identification of anomalous behavior.





#### Pod/container name similarity:

Attackers may attempt to hide their malicious activities by naming their backdoor pods in a way that resembles legitimate pods created by controllers like Deployments or DaemonSets. By blending in with existing pod naming conventions, attackers aim to avoid suspicion. Organizations should implement strict naming conventions and conduct regular audits to identify any discrepancies or suspicious pod/container names.





#### Connect from proxy server


To obfuscate their origin IP addresses, attackers may employ proxy servers, including anonymous networks like TOR, to communicate with applications or the Kubernetes API server. Organizations should consider implementing network security measures to monitor and restrict access from suspicious IP ranges or anonymous networks. Implementing intrusion detection and prevention systems (IDPS) and conducting regular threat intelligence analysis can aid in identifying proxy server usage by attackers.








### Credential access


The security of credentials is of paramount importance in Kubernetes environments. Attackers employ various techniques to steal credentials, including application credentials, service accounts, secrets, and cloud credentials. Safeguarding credential access is crucial to prevent unauthorized access, data breaches, and potential compromise of sensitive information. In this article, we will explore common credential access tactics and discuss strategies to enhance identity protection and mitigate the risks associated with credential theft in Kubernetes.





#### List Kubernetes secrets:


Kubernetes secrets are used to store sensitive information, such as passwords and connection strings, within the cluster. Attackers with appropriate permissions can retrieve these secrets from the API server, potentially gaining access to critical credentials. Organizations should adopt a defense-in-depth approach to secure secrets, including strong access controls, encryption, and regular auditing of secret configurations. Implementing fine-grained RBAC policies and limiting access to secrets based on the principle of least privilege can help mitigate the risk of unauthorized access.





#### Mount service principal:


In cloud deployments, attackers may exploit their access to a container in the cluster to gain unauthorized access to cloud credentials. For example, in Azure Kubernetes Service (AKS), each node contains a service principal credential. Organizations should implement robust security measures, such as secure cluster configurations, strict access controls, and regular rotation of service principal credentials, to prevent unauthorized access to cloud resources.






#### Access container service account:


Service accounts (SAs) are used to represent application identities within Kubernetes. By default, SAs are mounted to every pod in the cluster, allowing containers to interact with the Kubernetes API server. Attackers who gain access to a pod can extract the SA token and potentially perform actions within the cluster based on the SA's permissions. It is crucial to implement RBAC and enforce strong authentication mechanisms to mitigate the risk of unauthorized SA access. Regular audits and monitoring of SA permissions can help identify and remediate any potential security gaps.




#### Application credentials in configuration files:


Developers often store secrets, such as application credentials, in Kubernetes configuration files, including environment variables in the pod configuration. Attackers may attempt to access these configuration files to steal sensitive information. Organizations should promote secure coding practices, such as externalizing secrets to a secure secret management solution, and avoid storing credentials directly in configuration files. Implementing secure coding guidelines, regular security training for developers, and automated vulnerability scanning can help reduce the risk of unauthorized access to application credentials.







### Discovery

Discovery attacks pose a significant threat to the security of Kubernetes environments. Attackers employ various techniques to explore the environment, gain insights into the cluster's resources, and perform lateral movement to access additional targets. Understanding and mitigating these discovery tactics is crucial to bolster the overall security posture of Kubernetes deployments. In this article, we will delve into common discovery techniques and discuss strategies to enhance defense and thwart unauthorized exploration in Kubernetes.






#### Access the Kubernetes API server:


The Kubernetes API server acts as the gateway to the cluster, enabling interactions and resource management. Attackers may attempt to access the API server to gather information about containers, secrets, and other resources. Protecting the API server is paramount, and organizations should implement strong authentication mechanisms, robust access controls, and secure communication channels (TLS) to prevent unauthorized access and unauthorized retrieval of sensitive data.






#### Access Kubelet API:


Kubelet, running on each node, manages the execution of pods and exposes a read-only API service. Attackers with network access to the host can probe the Kubelet API to gather information about running pods and the node itself. To mitigate this risk, organizations should implement network segmentation and restrict network access to the Kubelet API, employing firewalls or network policies to allow communication only from trusted sources.







#### Network mapping:


Attackers may attempt to map the cluster network to gain insights into running applications and identify potential vulnerabilities. Implementing network segmentation, network policies, and utilizing network security solutions can help limit unauthorized network exploration within the cluster, reducing the attack surface and minimizing the impact of network mapping attempts.





#### Access Kubernetes dashboard:


The Kubernetes dashboard provides a web-based interface for managing and monitoring the cluster. Attackers who gain access to a container in the cluster may attempt to exploit the container's network access to access the dashboard pod. Organizations should secure the Kubernetes dashboard by implementing strong authentication, role-based access controls (RBAC), and secure network access policies to prevent unauthorized access and information leakage.




#### Instance Metadata API:


Cloud providers offer instance metadata services that provide information about virtual machine configurations and network details. Attackers who compromise a container may attempt to query the instance metadata API to gain insights into the underlying node. Protecting the metadata API is crucial, and organizations should implement network-level security controls, such as restricting access to the metadata service from within the VM only, to prevent unauthorized access and limit the exposure of sensitive information.









### Lateral movement


Lateral movement attacks pose a significant threat in containerized environments, allowing attackers to traverse through a victim's environment, gain unauthorized access to various resources, and potentially escalate privileges. Understanding and mitigating lateral movement tactics is crucial for bolstering the security of Kubernetes deployments. In this article, we will explore common techniques used by attackers for lateral movement and discuss strategies to enhance defense and minimize the impact of these attacks in Kubernetes.







#### Access the Kubernetes API server:


The Kubernetes API server acts as the gateway to the cluster, enabling interactions and resource management. Attackers may attempt to access the API server to gather information about containers, secrets, and other resources. Protecting the API server is paramount, and organizations should implement strong authentication mechanisms, robust access controls, and secure communication channels (TLS) to prevent unauthorized access and unauthorized retrieval of sensitive data.






#### Access Cloud Resources:


Attackers who compromise a container in the cluster may attempt to move laterally into the cloud environment itself. Organizations must implement strong access controls, employ least privilege principles, and regularly monitor cloud resources to detect and prevent unauthorized access attempts.








#### Container Service Account:


Attackers with access to a compromised container can leverage the mounted service account token to send requests to the Kubernetes API server and gain access to additional resources within the cluster. Securing container service accounts through RBAC and regularly rotating credentials can help mitigate the risk of lateral movement through compromised containers.






#### Cluster Internal Networking:


By default, Kubernetes allows communication between pods within the cluster. Attackers who gain access to a single container can leverage this networking behavior to traverse the cluster and target additional resources. Implementing network segmentation, network policies, and regular network monitoring can restrict unauthorized lateral movement within the cluster.





#### Application Credentials in Configuration Files:


Developers often store sensitive credentials in Kubernetes configuration files, such as environment variables in pod configurations. Attackers who gain access to these credentials can use them to move laterally and access additional resources both inside and outside the cluster. Employing secure secrets management practices, such as encrypting configuration files and limiting access to sensitive information, can mitigate the risk of credential-based lateral movement.






#### Writable Volume Mounts on the Host:


Attackers may attempt to exploit writable volume mounts within a compromised container to gain access to the underlying host. Securing host-level access controls, implementing strong container isolation, and regularly patching and hardening the underlying host can help mitigate the risk of lateral movement from containers to the host.






#### Access Kubernetes Dashboard:


Attackers with access to the Kubernetes dashboard can manipulate cluster resources and execute code within containers using the built-in "exec" capability. Securing the Kubernetes dashboard through strong authentication, access controls, and monitoring for suspicious activities can minimize the risk of unauthorized lateral movement through the dashboard.








#### Access Tiller Endpoint:


Tiller, the server-side component of Helm, may expose internal gRPC endpoints that do not require authentication. Attackers who can access a container connected to the Tiller service may exploit this vulnerability to perform unauthorized actions within the cluster. Organizations should consider migrating to Helm version 3, which removes the Tiller component and eliminates this specific risk.








### Impact


The Impact tactic in Kubernetes refers to techniques employed by attackers to disrupt, abuse, or destroy the normal behavior of the environment. These attacks can lead to data loss, resource abuse, and denial of service, resulting in severe consequences for organizations. Protecting Kubernetes deployments from such impact attacks is crucial to ensure the availability, integrity, and confidentiality of resources. In this article, we will explore common impact techniques used by attackers and discuss strategies to mitigate their effects in Kubernetes environments.








#### Data Destruction:



Attackers may target Kubernetes deployments to destroy critical data and resources. This can involve deleting deployments, configurations, storage volumes, or compute resources. To mitigate the risk of data destruction, it is essential to implement robust backup and disaster recovery mechanisms. Regularly backing up critical data, verifying backup integrity, and employing proper access controls can help in minimizing the impact of data destruction attacks.







#### Resource Hijacking:



Compromised resources within a Kubernetes cluster can be abused by attackers for malicious activities such as digital currency mining. Attackers who gain access to containers or have the permissions to create new containers may exploit these resources for unauthorized tasks. Implementing strict pod security policies, monitoring resource utilization, and regularly auditing containers for unauthorized activities can help detect and prevent resource hijacking attempts.









#### Denial of Service (DoS):



Attackers may launch DoS attacks to disrupt the availability of Kubernetes services. This can involve targeting containers, nodes, or the API server. To mitigate the impact of DoS attacks, it is crucial to implement network-level security measures such as ingress and egress filtering, rate limiting, and traffic monitoring. Additionally, implementing resource quotas, configuring horizontal pod autoscaling, and monitoring resource utilization can help in maintaining service availability and mitigating the impact of DoS attacks.





## Cloud Threat Matrix

![MITRE ATT&CK Cloud Threat Matrix](../../../assets/images/cloud-matrix.png)

The MITRE ATT&CK framework provides a comprehensive knowledge base of adversary tactics and techniques used in cyber attacks. 

### Initial Access:

#### Cloud Account Phishing

An attacker attempts to gain unauthorized access to a cloud account through phishing techniques.

#### Cloud Service Exploitation 

Attackers exploit vulnerabilities in cloud services to gain initial access.

### Execution

#### Remote Execution

Attackers execute code or commands on a cloud system remotely.

#### User Execution

Attackers trick a user into executing malicious code or commands on a cloud system.


### Persistence

#### Persistence through Cloud Resource 

Access: Attackers establish persistence by maintaining access to cloud resources or accounts.

#### Persistence through Cloud Service

Attackers use cloud services or features to establish persistence in the environment.


### Privilege Escalation

#### Access Cloud Service Permissions

Attackers escalate their privileges by manipulating cloud service permissions.

#### Container Escape

Attackers escape containerization to gain higher privileges in the cloud environment.


### Defense Evasion

#### Clear Cloud Logs

Attackers attempt to delete or manipulate logs in the cloud environment to evade detection.

#### Modify Cloud Trail

Attackers modify or tamper with cloud trail logs to hide their activities.


### Credential Access

#### Steal Cloud Service Credentials 

Attackers steal cloud service credentials to gain unauthorized access.

#### Capture Cloud Service Credentials

Attackers capture cloud service credentials through various means.


### Discovery

#### Cloud Service Discovery

Attackers discover cloud services and resources to gather information about the environment.

#### Container Discovery 

Attackers identify and explore containers within the cloud environment.


### Lateral Movement

#### Cloud Infrastructure Lateral Movement

Attackers move laterally between cloud resources and accounts.

#### Container-to-Container Lateral Movement

Attackers move laterally between containers within the cloud environment.

### Collection

#### Data from Cloud Storage Object

Attackers collect and exfiltrate data from cloud storage objects.

#### Data from Container

Attackers collect and exfiltrate data from containers in the cloud environment.

### Exfiltration:

#### Exfiltration Over Cloud Channel

Attackers exfiltrate data through cloud-based communication channels.

#### Exfiltration Over Other Network Medium

Attackers exfiltrate data using other network mediums within the cloud environment.




## Threat Hunting


## Shodan

A search engine for internet-connected devices that allows you to identify potential attack surfaces and vulnerabilities in your network.	


```
shodan scan submit --filename scan.json "port:22"
```

## VirusTotal

A threat intelligence platform that allows you to analyze files and URLs for potential threats and malware.	

```
curl --request POST --url 'https://www.virustotal.com/api/v3/urls' --header 'x-apikey: YOUR_API_KEY' --header 'content-type: application/json' --data '{"url": "https://example.com"}'
```

## ThreatConnect

A threat intelligence platform that allows you to collect, analyze, and share threat intelligence with your team and community.	

```
curl -H "Content-Type: application/json" -X POST -d '{"name": "Example Threat Intel", "description": "This is an example threat intelligence report."}' https://api.threatconnect.com/api/v2/intelligence
```

## MISP

An open-source threat intelligence platform that allows you to collect, store, and share threat intelligence with your team and community.	

```
curl -X POST 'http://misp.local/events/restSearch' -H 'Authorization: YOUR_API_KEY' -H 'Content-Type: application/json' -d '{ "returnFormat": "json", "eventid": [1,2,3], "enforceWarninglist":0 }'
```


## ChatGPT

### Generate Yara Rule

- [ ] Specify the objective of the YARA rule. For this example, let's create a rule to detect a specific type of malware based on its behavior.

Prompt: "Please provide a brief description of the malware behavior you want to detect."


- [ ] Identify indicators of the malware, such as file names, strings, or patterns that are characteristic of the malware. This information will be used in the YARA rule.



Prompt: "What are some specific indicators or patterns associated with the malware?"



- [ ] Start the YARA rule by defining metadata such as the rule name, description, and author. Add this information to the rule.yar file.



Prompt: "Please provide the rule name, description, and author for the YARA rule."



- [ ] Define the condition or logic that will trigger the rule when a match is found. Use the indicators identified in Step 2 and YARA syntax to specify the condition.



Prompt: "Please provide the condition for the YARA rule using the indicators and YARA syntax."



- [ ] Optionally, add tags to the YARA rule to provide additional information or categorization. Tags can be used to group related rules together.

Prompt: "If applicable, please add any relevant tags to the YARA rule."




- [ ] Test the YARA rule against sample files or known malware to ensure it detects the intended behavior.

Prompt: "Please test the YARA rule against sample files or known malware to verify its effectiveness."



- [ ] Refine the YARA rule based on the test results and iterate on the steps as necessary to improve its accuracy and coverage.



Prompt: "Based on the test results, do you need to refine or iterate on the YARA rule?"





### Code Analysis


- [ ] Acquire a malware sample that you want to analyze. This can be a file, script, or any other form of malicious code.

Prompt: "Please provide the malware sample you want to analyze."



- [ ] Create a secure and isolated environment to analyze the malware sample. This can be a virtual machine, sandbox, or container.



Prompt: "How would you like to set up the secure environment? (e.g., virtual machine, sandbox)"




- [ ] Install the necessary tools for malware analysis. This typically includes disassemblers, debuggers, and code analysis tools.



Prompt: "Please list the specific tools you would like to install for malware code analysis."




- [ ] Extract the malware from its container or packaging and inspect its components, such as executable files, scripts, or configuration files.



Prompt: "Please extract the malware sample and provide a brief overview of its components."




- [ ] Use a disassembler or decompiler tool to analyze the malware's code and convert it into a more readable format for analysis.



Prompt: "Which disassembler or decompiler tool would you like to use for the analysis?"




- [ ] Examine the code of the malware to identify its behavior, functions, and potential vulnerabilities. Look for any obfuscation techniques or anti-analysis measures used by the malware.



Prompt: "What specific aspects of the malware code would you like to analyze? (e.g., behavior, vulnerabilities)"





- [ ] If necessary, set up a debugger to trace the execution of the malware and understand its runtime behavior. This step may require advanced knowledge and specialized tools.





Prompt: "Do you want to debug and trace the execution of the malware? If yes, please specify the debugger tool."






- [ ] Document your findings during the malware code analysis process, including identified behaviors, potential risks, and any other relevant information. Generate a report summarizing the analysis.





Prompt: "Please document your findings and generate a report summarizing the malware code analysis."





- [ ] Based on the analysis, develop and apply security mitigations to protect against the malware's attack vectors. This may involve patching vulnerabilities, updating security measures, or implementing specific controls.

Prompt: "What security mitigations would you recommend based on the analysis?"








### Generate Script




- [ ] Acquire a malware sample that you want to analyze. This can be a file, script, or any other form of malicious code.

Prompt: "Please provide the malware sample you want to analyze."





- [ ] Extract the malware from its container or packaging and inspect its components, such as executable files, scripts, or configuration files.



Prompt: "Please extract the malware sample and provide a brief overview of its components."




- [ ] Examine the code of the malware to identify its behavior, functions, and potential vulnerabilities. Look for any obfuscation techniques or anti-analysis measures used by the malware.

Prompt: "What specific aspects of the malware code would you like to analyze? (e.g., behavior, vulnerabilities)"



- [ ] If necessary, set up a debugger to trace the execution of the malware and understand its runtime behavior. This step may require advanced knowledge and specialized tools.

Prompt: "Do you want to debug and trace the execution of the malware? If yes, please specify the debugger tool."




- [ ] Document your findings during the malware code analysis process, including identified behaviors, potential risks, and any other relevant information. Generate a report summarizing the analysis.

Prompt: "Please document your findings and generate a report summarizing the malware code analysis."



- [ ] Based on the analysis, develop and apply security mitigations to protect against the malware's attack vectors. This may involve patching vulnerabilities, updating security measures, or implementing specific controls.

Prompt: "What security mitigations would you recommend based on the analysis?"






### Log Analysis


- [ ] Preprocess the log files to extract the necessary information and make them more readable. Use tools like awk, sed, or grep to filter and format the log data. For example:


```
$ awk '{print $4, $7}' access.log > formatted_logs.txt
```


- [ ]  Start by exploring the log data to understand its structure and content. Use commands like head, tail, or cat to view the log files. For example:


```
$ head formatted_logs.txt
```

Prompt: "Please provide a brief overview of the log data structure and format."




- [ ] Perform statistical analysis on the log data to gain insights. Use tools like grep, sort, or uniq to extract useful information. For example:


```
$ grep '404' formatted_logs.txt | wc -l
```

Prompt: "Can you provide the count of HTTP 404 errors in the log data?"



- [ ] Apply pattern matching techniques to identify specific events or anomalies. Use commands like grep or regular expressions to search for patterns. For example:


```
$ grep -E '(\b\d{3}\b){4}' formatted_logs.txt
```

Prompt: "Please identify any IP addresses in the log data."



- [ ] Perform time-based analysis to identify trends or suspicious activities. Use commands like awk or date to manipulate timestamps. For example:


```
$ awk '{print $4, $7}' access.log > formatted_logs.txt
```

Prompt: "Can you provide a distribution of log events based on the hour of the day?"





- [ ] Engage in an interactive investigation by asking questions or seeking specific information. Use prompts like:


* "Can you identify any failed login attempts in the log data?"
* "Please provide the top 10 most accessed URLs in the log data."
* "Are there any user-agents associated with suspicious activities?"



- [ ] Create visualizations to present the findings. Use tools like matplotlib, gnuplot, or online visualization platforms. For example:


```
import matplotlib.pyplot as plt

# Code to generate a bar chart or line graph based on the log analysis results
```

Prompt: "Can you create a bar chart showing the distribution of log events over time?"





## Databases

* https://otx.alienvault.com/
* https://exchange.xforce.ibmcloud.com/
* https://github.com/certtools/intelmq-feeds-documentation
* https://sca.analysiscenter.veracode.com/vulnerability-database/search#
* https://vulmon.com
* https://github.com/advisories


## Playbook

* https://gitlab.com/syntax-ir/playbooks


## Log

* https://github.com/logpai/loghub/tree/master


## References

* https://socradar.io






