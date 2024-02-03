---
layout: default
title: LLM
parent: Rules
---

# Большая языковая модель (LLM)
{: .no_toc }



## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---






## LLM01:2023 - Оперативные инъекции


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```c
user_prompt = input("Enter your request: ")
response = LLM_model.generate_prompt(user_prompt)
print(response)
```

В приведенном выше коде пользователю предлагается ввести свой запрос, который затем напрямую используется в качестве запроса для модели LLM без какой-либо проверки или санации. Этот код подвержен инъекциям запроса, поскольку злоумышленник может ввести вредоносный запрос, чтобы манипулировать поведением LLM или извлечь конфиденциальную информацию.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```python
import re

# Определите шаблон регулярного выражения для проверки вводимых пользователем данных
input_pattern = r'^[a-zA-Z0-9\s\.,!?]+$'

def sanitize_input(user_input):
    # Удалите из вводимых данных все специальные символы и знаки
    sanitized_input = re.sub(r'[^\w\s\.,!?]', '', user_input)
    return sanitized_input.strip()

def validate_input(user_input):
    # Проверка соответствия вводимых пользователем данных заданному шаблону
    return re.match(input_pattern, user_input) is not None

user_prompt = input("Enter your request: ")

# Дезинфекция и проверка вводимых пользователем данных
sanitized_prompt = sanitize_input(user_prompt)

if validate_input(sanitized_prompt):
    response = LLM_model.generate_prompt(sanitized_prompt)
    print(response)
else:
    print("Invalid input. Please enter a valid request.")
```


В соответствующем коде было сделано несколько изменений для предотвращения инъекций:

1.  Для проверки вводимых пользователем данных определен шаблон регулярного выражения (`input_pattern`). Он допускает только буквенно-цифровые символы, пробелы, запятые, точки, восклицательные и вопросительные знаки.
    
2.  Функция `Sanitize_input` удаляет из вводимых пользователем данных любые специальные символы и знаки, гарантируя, что они содержат только разрешенные символы.
    
3.  Функция `validate_input` проверяет, соответствует ли санированный ввод заданному шаблону. Если да, то вызывается модель LLM для генерации подсказки и выдачи ответа. В противном случае выводится сообщение об ошибке.
    

Проверяя и санируя пользовательский ввод, соответствующий код защищает от инъекций подсказок, гарантируя, что в модель LLM передаются только безопасные и ожидаемые подсказки.





## LLM02:2023 - Утечка данных


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```python
user_prompt = input("Enter your request: ")
response = LLM_model.generate_prompt(user_prompt)
print(response)
```

В приведенном выше коде пользователю предлагается ввести свой запрос, который затем напрямую используется в качестве запроса для модели LLM без какой-либо проверки или санации. Этот код подвержен инъекциям запроса, поскольку злоумышленник может ввести вредоносный запрос, чтобы манипулировать поведением LLM или извлечь конфиденциальную информацию.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```python
import re

user_prompt = input("Enter your request: ")

# Проверьте, не содержит ли пользовательская подсказка конфиденциальную информацию
if re.search(r'\b(?:password|credit card|social security)\b', user_prompt, re.IGNORECASE):
    print("Error: Your request contains sensitive information.")
else:
    response = LLM_model.generate_prompt(user_prompt)
    print(response)
```


В соответствующем уязвимом коде предпринята попытка предотвратить утечку данных путем проверки наличия в приглашении пользователя конфиденциальной информации с помощью регулярных выражений. Если запрос пользователя соответствует шаблонам с конфиденциальной информацией (например, "пароль", "кредитная карта" или "социальное страхование"), то вместо ответа выводится сообщение об ошибке. Однако код по-прежнему уязвим, поскольку само сообщение об ошибке может раскрыть наличие конфиденциальной информации во вводимых пользователем данных.




## LLM03:2023 - Неправильная песочница


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```python
import os

user_prompt = input("Enter your command: ")
os.system(user_prompt)
```

В этом несовместимом коде пользователю предлагается ввести команду, а функция `os.system()` используется для непосредственного выполнения введенного пользователем текста. Нет никакой надлежащей "песочницы" или ограничений на команду пользователя, что позволяет ему выполнить любую команду системного уровня, которую он пожелает. Отсутствие "песочницы" подвергает базовую систему потенциальным несанкционированным действиям и ставит под угрозу ее безопасность.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```python
import subprocess

user_prompt = input("Enter your command: ")
subprocess.run(user_prompt, shell=False)
```


В соответствующем уязвимости коде вместо функции `os.system()` используется функция `subprocess.run()`. Параметр `shell` имеет значение `False` для предотвращения уязвимостей инъекции команд. Однако этот код все еще уязвим, поскольку в нем отсутствует должная "песочница" или ограничение на команды пользователя. Пользователь может выполнить любую команду в рамках разрешенных привилегий запущенного процесса.




## LLM04:2023 - Выполнение несанкционированного кода


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```python
user_prompt = input("Enter your command: ")
exec(user_prompt)
```

В коде, не соответствующем требованиям, пользовательский ввод напрямую передается в функцию `exec()`, которая выполняет команду как есть, без какой-либо проверки или санации. Этот код уязвим для несанкционированного выполнения кода, поскольку злоумышленник может создать вредоносную команду, которая будет выполнена LLM.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```python
import subprocess

def execute_command(command):
    subprocess.run(command, shell=True)

def process_user_prompt(user_prompt):
    # Дезинфекция и проверка пользовательского ввода перед выполнением команды
    if not valid_input(user_prompt):
        print("Invalid input. Please try again.")
        return
    
    execute_command(user_prompt)

def valid_input(user_prompt):
    # Реализуйте здесь логику проверки ввода
    # Убедитесь, что user_prompt не содержит никаких вредоносных команд или неавторизованного кода

    # Пример валидации: Ограничение определенных команд или проверка на наличие шаблонов, указывающих на вредоносный ввод
    if "rm -rf" in user_prompt:
        return False

    return True

user_prompt = input("Enter your command: ")
process_user_prompt(user_prompt)
```


В совместимом уязвимом коде добавлена проверка и санация ввода. Функция `valid_input()` проверяет, безопасен ли пользовательский ввод и не содержит ли он потенциально вредоносных команд или неавторизованного кода. Если ввод признан корректным, команда выполняется с помощью функции `execute_command()`, которая использует метод `subprocess.run()` с аргументом `shell=True`. Функция `valid_input()` может быть настроена на включение дополнительной логики проверки в зависимости от конкретных требований и потенциальных угроз.



## LLM05:2023 - Уязвимости подделки запросов на стороне сервера (SSRF)


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```python
import requests

def fetch_data(url):
    response = requests.get(url)
    return response.text

user_input = input("Enter the URL to fetch data from: ")
data = fetch_data(user_input)
print(data)
```

Несоответствующий код напрямую использует URL-адрес, предоставленный пользователем, для выполнения запроса без какой-либо проверки или ограничения. Это позволяет злоумышленнику предоставить вредоносный URL, который может быть направлен на внутренние системы, API или конфиденциальные ресурсы.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```python
import requests

ALLOWED_DOMAINS = ["example.com", "api.example.com"]

def fetch_data(url):
    response = requests.get(url)
    return response.text

def is_url_allowed(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    return domain in ALLOWED_DOMAINS

user_input = input("Enter the URL to fetch data from: ")

if is_url_allowed(user_input):
    data = fetch_data(user_input)
    print(data)
else:
    print("Access to the specified URL is not allowed.")
```


Соответствующий уязвимости код представляет базовый механизм проверки URL. Он определяет список разрешенных доменов (`ALLOWED_DOMAINS`) и проверяет, принадлежит ли предоставленный пользователем URL к одному из этих доменов. Если URL разрешен, код переходит к получению данных. В противном случае выводится сообщение о том, что доступ к указанному URL не разрешен.


## LLM06:2023 - Чрезмерное доверие к контенту, создаваемому LLM


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```python
user_input = input("Enter your question: ")
response = LLM_model.generate_response(user_input)
print(response)
```

В приведенном выше несоответствующем коде наблюдается чрезмерная зависимость от содержимого, генерируемого LLM. Введенные пользователем данные напрямую передаются в модель LLM без какой-либо проверки или человеческого контроля. Сгенерированный ответ затем печатается без дальнейшей проверки или анализа, что приводит к потенциальным рискам, связанным с чрезмерным доверием к содержимому, сгенерированному LLM.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```python
user_input = input("Enter your question: ")
response = LLM_model.generate_response(user_input)
reviewed_response = review_content(response)
print(reviewed_response)

def review_content(content):
    # Внедрить процесс проверки человеком для подтверждения и проверки контента, созданного LLM.
    # Проверка точности, фактичности и потенциальной необъективности
    # Вносите исправления и дополнения по мере необходимости
    return content
```


В полном коде, соответствующем требованиям уязвимости, сделана попытка устранить риски, связанные с чрезмерной зависимостью от контента, генерируемого LLM. Вводимые пользователем данные по-прежнему передаются в модель LLM для генерации ответа. Однако сгенерированный ответ затем передается через функцию `review_content()`, которая представляет собой процесс человеческой проверки. Эта функция позволяет подтвердить, проверить и исправить сгенерированный LLM контент. Прошедший проверку ответ распечатывается или используется в дальнейшем в приложении.



## LLM07:2023 - Неправильное согласование ИИ


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```python
# Несоответствующий код: Неправильное согласование ИИ

def generate_response(user_prompt):
    # Произвольные и плохо сформулированные цели
    if user_prompt == "get_personal_info":
        return get_personal_info()
    elif user_prompt == "generate_random_number":
        return generate_random_number()
    else:
        return "Invalid prompt"

def get_personal_info():
    # Код для получения и возврата личной информации
    ...

def generate_random_number():
    # Код для генерации случайного числа
    ...
```

Несоответствующий код демонстрирует неправильное согласование ИИ, поскольку в нем отсутствуют четко определенные цели для LLM. В нем произвольно и плохо определены цели, где различные пользовательские подсказки вызывают различные действия без четкого соответствия желаемым результатам. Код не учитывает такие факторы, как авторизация или проверка пользователя, что приводит к потенциальным проблемам безопасности и конфиденциальности.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```python
# Соответствующий уязвимый код:: Улучшенное согласование искусственного интеллекта

def generate_response(user_prompt):
    if user_prompt == "get_personal_info":
        return handle_personal_info_request()
    elif user_prompt == "generate_random_number":
        return handle_random_number_request()
    else:
        return "Invalid prompt"

def handle_personal_info_request():
    # Выполнение необходимых проверок и валидаций
    if user_is_authorized():
        return retrieve_personal_info()
    else:
        return "Unauthorized access"

def retrieve_personal_info():
    # Код для получения и возврата личной информации
    ...

def handle_random_number_request():
    # Выполнение необходимых проверок и валидаций
    if user_is_authorized():
        return generate_random_number()
    else:
        return "Unauthorized access"

def generate_random_number():
    # Код для генерации случайного числа
    ...
```


Соответствующий уязвимый полный код улучшает согласование ИИ, рассматривая более конкретные и четко определенные цели. Он вводит отдельные функции для обработки различных пользовательских запросов, таких как "get_personal_info" и "generate_random_number". Каждая функция выполняет необходимые проверки и валидации перед выполнением соответствующего действия. Например, перед получением персональной информации или генерацией случайного числа код проверяет, имеет ли пользователь право выполнять эти действия. Это гарантирует, что поведение LLM соответствует поставленным целям и включает в себя меры безопасности.



## LLM08:2023 - Недостаточный контроль доступа


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```python
def generate_response(user_input):
    response = LLM_model.generate_prompt(user_input)
    return response

user_input = input("Enter your request: ")
response = generate_response(user_input)
print(response)
```

В приведенном выше несоответствующем коде не реализовано никаких средств контроля доступа. Любой пользователь может ввести запрос, а функция `generate_response()` напрямую передает пользовательский ввод в модель LLM без каких-либо проверок аутентификации или авторизации. Отсутствие контроля доступа позволяет любому пользователю, авторизованному или неавторизованному, взаимодействовать с LLM и получать ответы.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```python
def generate_response(user_input, user_role):
    if user_role == "admin":
        response = LLM_model.generate_prompt(user_input)
        return response
    else:
        return "Unauthorized access"

def authenticate_user(username, password):
    # Код для аутентификации пользователя

def get_user_role(username):
    # Код для получения роли пользователя

def main():
    username = input("Username: ")
    password = input("Password: ")

    if authenticate_user(username, password):
        user_role = get_user_role(username)
        user_input = input("Enter your request: ")

        response = generate_response(user_input, user_role)
        print(response)
    else:
        print("Authentication failed")

if __name__ == "__main__":
    main()
```


В уязвимом коде, соответствующем требованиям, реализованы средства управления доступом, гарантирующие, что только аутентифицированные и авторизованные пользователи могут взаимодействовать с LLM. Функция `generate_response()` теперь принимает дополнительный параметр `user_role`, который представляет роль пользователя. Функция проверяет, имеет ли пользователь роль "admin", прежде чем генерировать ответ LLM. Если пользователь имеет роль "admin", ответ генерируется и возвращается. В противном случае возвращается сообщение "Unauthorized access".

Функция `main()` обрабатывает процесс аутентификации пользователя, запрашивая имя пользователя и пароль. Она вызывает функцию `authenticate_user()` для проверки учетных данных и получения роли пользователя с помощью функции `get_user_role()`. Если аутентификация прошла успешно, пользователю предлагается ввести запрос, и вызывается функция `generate_response()` с введенными пользователем данными и ролью.



## LLM09:2023 - Неправильная обработка ошибок


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```python
# Noncompliant code
try:
    # Код, который может вызвать ошибку
    result = perform_operation()
    print("Operation completed successfully!")
except Exception as e:
    # Отображение подробного сообщения об ошибке для пользователя
    print(f"An error occurred: {str(e)}")
```

Приведенный выше код, не отвечающий требованиям, демонстрирует неправильные методы обработки ошибок. Когда во время вызова функции `perform_operation()` возникает ошибка, код перехватывает исключение и выводит пользователю подробное сообщение об ошибке с помощью `print(f "Произошла ошибка: {str(e)}")`. Такой подход раскрывает конфиденциальную информацию и потенциально раскрывает пользователю детали реализации, что может быть использовано злоумышленниками.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```python
# Соответствующий код
import logging

try:
    # Код, который может вызвать ошибку
    result = perform_operation()
    print("Operation completed successfully!")
except Exception as e:
    # Запись сообщения об ошибке в журнал для внутреннего использования
    logging.exception("An error occurred during the operation")
    # Отображение общего сообщения об ошибке для пользователя
    print("An error occurred. Please try again later.")
```


В совместимом уязвимом коде решена проблема неправильной обработки ошибок. В нем реализовано протоколирование с помощью модуля `logging` для сбора подробной информации об ошибке для внутреннего использования. Вместо того чтобы выводить пользователю конкретное сообщение об ошибке, он выдает общее сообщение об ошибке, например "Произошла ошибка. Пожалуйста, повторите попытку позже". Это предотвращает утечку конфиденциальной информации пользователю, но при этом указывает на то, что ошибка произошла.



## LLM10:2023 - Заражение учебных данных


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```python
# Несоответствующий код - заражение учебных данных
import random

def get_training_data():
    # Получение обучающих данных из ненадежного источника
    training_data = untrusted_source.get_data()
    
    # Внедрение вредоносных примеров в обучающие данные
    poisoned_data = training_data + malicious_examples
    
    return poisoned_data

def train_model():
    data = get_training_data()
    
    # Обучите модель, используя зараженные данные
    model.train(data)
```

В несовместимом коде данные для обучения берутся из недоверенного источника, который может быть изменен с целью внедрения вредоносных примеров. Код объединяет недоверенные данные с вредоносными примерами, в результате чего получается отравленный набор данных. Это позволяет злоумышленнику манипулировать поведением модели и вносить в нее уязвимости или погрешности.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```python
# Соответствующий уязвимости код - обучение заражённым данным
import random

def get_training_data():
    # Получите данные для обучения из надежного источника
    training_data = trusted_source.get_data()
    
    return training_data

def sanitize_data(data):
    # Применяйте методы обеззараживания данных для устранения потенциальных уязвимостей или предвзятости
    sanitized_data = perform_sanitization(data)
    
    return sanitized_data

def train_model():
    data = get_training_data()
    
    # Проведите дезинфекцию обучающих данных, чтобы устранить возможные заражения или необъективность
    sanitized_data = sanitize_data(data)
    
    # Обучите модель, используя обеззараженные данные
    model.train(sanitized_data)
```


В совместимом уязвимом коде данные для обучения берутся из надежного источника, что гарантирует их целостность и надежность. Затем данные проходят процесс санирования для удаления потенциальных уязвимостей, предвзятости или вредоносного содержимого. Санированные данные используются для обучения модели, что снижает риск отравления обучающих данных.
