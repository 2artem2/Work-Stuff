---
layout: default
title: Python
parent: Rules
---

# Python
{: .no_toc }



## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---





## Раскрытие конфиденциальной информации

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
@app.route('/users/<id>', methods=['GET'])
def get_user(id):
    user = db.get_user(id)
    
    if user:
        return jsonify(user)
    else:
        return jsonify({'error': 'User not found'}), 404

```

Пример кода, не соответствующий требованиям, раскрывает конфиденциальную информацию, возвращая полный объект пользователя в виде ответа в формате JSON. Это может привести к раскрытию конфиденциальных данных, таких как пароли, адреса электронной почты или другие частные данные пользователя. Если неавторизованный пользователь сделает запрос к этой конечной точке с действительным идентификатором пользователя, он получит полный объект пользователя, включая конфиденциальную информацию.


Чтобы решить эту проблему, приведем пример совместимого кода:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
@app.route('/users/<id>', methods=['GET'])
def get_user(id):
    user = db.get_user(id)
    
    if user:
        sanitized_user = {
            'id': user['id'],
            'name': user['name']
            # Включайте только необходимую неконфиденциальную информацию
        }
        return jsonify(sanitized_user)
    else:
        return jsonify({'error': 'User not found'}), 404
```


Соответствующий код решает эту проблему путем санации объекта пользователя перед отправкой ответа. Вместо того чтобы возвращать полный объект пользователя, он создает новый словарь (sanitized_user), который содержит только необходимую нечувствительную информацию, такую как идентификатор и имя пользователя. Таким образом, конфиденциальные данные не попадают к неавторизованным пользователям. Применяя методы санации данных, код обеспечивает передачу только необходимой информации и надлежащую защиту конфиденциальных данных.





## Вставка конфиденциальной информации в отправленные данные

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
def send_email(user_email, message):
    subject = "Important Message"
    body = f"Hello {user_email},\n\n{message}\n\nRegards,\nAdmin"
    
    # Код для отправки электронной почты с помощью SMTP
    # ...
```

Пример кода, не соответствующий требованиям, вставляет конфиденциальную информацию, например адрес электронной почты пользователя, непосредственно в тело письма без надлежащей проверки или защиты. В результате конфиденциальная информация может попасть к нежелательным получателям, если письмо будет перехвачено или если почтовый клиент не обеспечивает безопасную обработку данных.


Чтобы решить эту проблему, вот пример совместимого кода:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
def send_email(user_email, message):
    subject = "Important Message"
    body = f"Hello,\n\n{message}\n\nRegards,\nAdmin"
    
    # Код для отправки электронной почты с помощью SMTP
    # ...
```


Код, соответствующий требованиям, исключает вставку адреса электронной почты пользователя в тело письма. Вместо этого в теле письма используется общее приветствие без прямой ссылки на адрес электронной почты пользователя. Избегая включения конфиденциальной информации в отправляемые данные, совместимый код гарантирует, что конфиденциальная информация не будет раскрыта или утечка во время коммуникации. Важно бережно относиться к конфиденциальным данным и следовать лучшим практикам защиты данных и конфиденциальности.






## Подделка межсайтовых запросов (CSRF)

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
from flask import Flask, render_template, request

app = Flask(__name__)

@app.route('/transfer', methods=['POST'])
def transfer():
    # Перевод средств
    amount = request.form['amount']
    destination_account = request.form['destination_account']
    # ... логика перевода средств ...

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run()
```

Несоответствующий код не имеет соответствующей защиты от CSRF. Функция transfer() выполняет перевод средств на основе данных формы, переданных через POST-запрос. Однако в ней не реализован механизм защиты от атак Cross-Site Request Forgery. Злоумышленник может создать вредоносный веб-сайт, который автоматически отправляет форму в конечную точку /transfer, обманывая жертву, чтобы она неосознанно инициировала перевод средств.


Чтобы решить эту проблему, вот пример совместимого кода:



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
from flask import Flask, render_template, request
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
csrf = CSRFProtect(app)

@app.route('/transfer', methods=['POST'])
@csrf.exempt
def transfer():
    # Перевод средств
    amount = request.form['amount']
    destination_account = request.form['destination_account']
    # ... логика перевода средств ...

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run()
```


Для обеспечения защиты от CSRF в совместимом коде используется расширение CSRFProtect из Flask-WTF. Декоратор @csrf.exempt используется для функции transfer(), чтобы освободить ее от защиты от CSRF, поскольку она является намеренной конечной точкой API. Благодаря включению защиты от CSRF, совместимый код снижает риск атак CSRF, проверяя подлинность запросов и убеждаясь, что они поступают с того же сайта, что и отправка формы.






## Использование жестко закодированного пароля

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
def login(username, password):
    if username == 'admin' and password == 'password123':
        # Вход в систему успешный
        return True
    else:
        # Вход в систему не удался
        return False
```

Несоответствующий код напрямую сравнивает предоставленные имя пользователя и пароль с жестко закодированными значениями ('admin' и 'password123'). Такой подход представляет собой угрозу безопасности, поскольку конфиденциальные учетные данные раскрываются непосредственно в исходном коде. Любой человек, имеющий доступ к исходному коду, может легко получить учетные данные, поставив под угрозу безопасность системы.


Чтобы решить эту проблему, приведем пример совместимого кода:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
import getpass

def login(username, password):
    stored_password = retrieve_password_from_database(username)
    if password_matches(stored_password, password):
        # Вход в систему успешный
        return True
    else:
        # Вход в систему не удался
        return False

def retrieve_password_from_database(username):
    # Код для получения хэшированного пароля из базы данных
    # ...

def password_matches(stored_password, entered_password):
    # Код для сравнения сохраненного пароля с введенным паролем
    # ...

if __name__ == '__main__':
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    login(username, password)
```

Соответствующий код позволяет избежать использования жестко закодированных паролей непосредственно в исходном коде. Вместо этого он отделяет логику аутентификации от хранения и сравнения паролей. Функция retrieve_password_from_database() извлекает сохраненный пароль для заданного имени пользователя из защищенной базы данных. Функция password_matches() сравнивает введенный пароль с сохраненным паролем, используя соответствующие безопасные методы хэширования и сравнения.

Благодаря такому подходу пароль надежно хранится в базе данных, а код не раскрывает конфиденциальную информацию.







## Сломанный или рискованный криптоалгоритм

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
import base64
from Crypto.Cipher import DES

def encrypt_data(data, key):
    cipher = DES.new(key, DES.MODE_ECB)
    encrypted_data = cipher.encrypt(data)
    return base64.b64encode(encrypted_data).decode('utf-8')

def decrypt_data(encrypted_data, key):
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_data = cipher.decrypt(base64.b64decode(encrypted_data))
    return decrypted_data.decode('utf-8')
```


Несоответствующий код использует алгоритм DES (Data Encryption Standard), который считается нерабочим и небезопасным для большинства криптографических целей. Кроме того, в коде используется режим ECB (Electronic Codebook), который не обеспечивает достаточной защиты от некоторых атак. Для кодирования и декодирования зашифрованных данных используется модуль base64.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt_data(data, key):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.GCM(), backend=backend)
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return base64.urlsafe_b64encode(encrypted_data).decode('utf-8')

def decrypt_data(encrypted_data, key):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.GCM(), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(base64.urlsafe_b64decode(encrypted_data)) + decryptor.finalize()
    return decrypted_data.decode('utf-8')
```

В совместимом коде используется библиотека cryptography, которая предоставляет более безопасный и современный криптографический API. В ней используется алгоритм AES (Advanced Encryption Standard) с режимом GCM (Galois/Counter Mode), который считается более безопасным, чем DES. Функции urlsafe_b64encode и urlsafe_b64decode из модуля base64 используются для кодирования и декодирования зашифрованных данных, соответственно.








## Недостаточная энтропия

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
import random

def generate_random_password(length):
    password = ''
    for _ in range(length):
        password += random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890')
    return password
```


Несоответствующий код пытается сгенерировать случайный пароль путем многократного выбора символа из ограниченного набора символов. Однако такой подход не обеспечивает достаточной энтропии, поскольку выбор символов ограничен алфавитно-цифровыми символами. Полученные пароли могут не обладать достаточно сильным случайным распределением, что делает их более восприимчивыми к атакам методом "грубой силы".






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
import secrets
import string

def generate_random_password(length):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password
```

Соответствующий код повышает энтропию генерируемого пароля за счет использования модуля секретов и более широкого набора символов. Он сочетает строчные и прописные буквы, цифры и знаки препинания для формирования более разнообразного набора символов. Функция secrets.choice используется для безопасного выбора символа из расширенного набора для каждой позиции в пароле. Такой подход обеспечивает более высокий уровень случайности и повышает стойкость генерируемых паролей.






## Межсайтовый скриптинг (XSS)

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
def generate_html_output(input_data):
    html = "<div>" + input_data + "</div>"
    return html
```

Несоответствующий код принимает параметр input_data и напрямую конкатенирует его в HTML-строку без надлежащей санации или экранирования. Такой подход может привести к XSS-уязвимости, поскольку позволяет злоумышленнику внедрить вредоносные скрипты или HTML-код в выводимые данные. Если input_data содержит управляемый пользователем ввод, злоумышленник может создать ввод, включающий JavaScript-код или HTML-теги, которые будут выполнены, когда сгенерированный HTML будет отображен браузером.







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
import html

def generate_html_output(input_data):
    escaped_data = html.escape(input_data)
    html = "<div>" + escaped_data + "</div>"
    return html
```


Соответствующий код использует функцию html.escape для правильной санации входных данных, заменяя специальные символы на соответствующие им HTML-сущности. Этот шаг гарантирует, что любой управляемый пользователем ввод будет рассматриваться как обычный текст и не будет интерпретироваться как код HTML или JavaScript при отображении в браузере. Благодаря экранированию входных данных совместимый код снижает риск XSS-атак, предотвращая выполнение вредоносных скриптов или непреднамеренную интерпретацию HTML-тегов.







## SQL-инъекция

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
import sqlite3

def get_user_data(username):
    conn = sqlite3.connect('mydb.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    result = cursor.fetchall()
    conn.close()
    return result
```

Несоответствующий код принимает параметр username и напрямую конкатенирует его в SQL-запрос без использования параметризованных запросов или надлежащей проверки ввода. Такой подход может привести к уязвимости SQL-инъекции, поскольку позволяет злоумышленнику манипулировать запросом, предоставляя вредоносный ввод. Злоумышленник может изменить параметр имени пользователя и включить в него дополнительные SQL-запросы, изменив предполагаемое поведение запроса или даже получив несанкционированный доступ к базе данных.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
import sqlite3

def get_user_data(username):
    conn = sqlite3.connect('mydb.db')
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    result = cursor.fetchall()
    conn.close()
    return result
```

Соответствующий код использует параметризованные запросы с заполнителями для безопасной передачи параметра username в SQL-запрос. Вместо того чтобы непосредственно конкатенировать вводимые данные в строку запроса, используется заполнитель ?, а фактическое значение передается отдельно в качестве параметра методу execute. Это гарантирует, что вводимые данные должным образом обеззараживаются и рассматриваются как данные, что исключает риск атак SQL-инъекций. Соответствующий код защищает от несанкционированных манипуляций со структурой запроса и обеспечивает безопасное выполнение предполагаемого SQL-запроса.





## Внешнее управление именем или путем файла

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
import os

def delete_file(file_name):
    path = "/path/to/files/" + file_name
    if os.path.exists(path):
        os.remove(path)
        print("File deleted.")
    else:
        print("File not found.")
```


Несоответствующий код принимает параметр file_name и напрямую конкатенирует его в переменную path без надлежащей проверки или санации. Такой подход может привести к уязвимости внешнего управления именем файла или путем, поскольку злоумышленник может манипулировать параметром file_name для доступа или удаления произвольных файлов в системе. Предоставив на вход специально созданный параметр file_name, злоумышленник потенциально может перемещаться по каталогам или непреднамеренно удалять конфиденциальные файлы.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
import os
import os.path

def delete_file(file_name):
    base_path = "/path/to/files/"
    path = os.path.join(base_path, file_name)

    if os.path.exists(path) and os.path.isfile(path):
        os.remove(path)
        print("File deleted.")
    else:
        print("File not found.")
```

Соответствующий код устраняет уязвимость с помощью функции os.path.join для безопасного конкатенации параметра file_name с базовым путем. Это гарантирует, что результирующий путь к файлу будет правильно сформирован независимо от входных данных. Кроме того, в совместимый код включены проверки на существование файла и на то, что он является обычным файлом (os.path.isfile), прежде чем выполнять с ним какие-либо операции. Это снижает риск непреднамеренного доступа к файлу или его удаления и обеспечивает более безопасный подход к работе с файлами в Python.






## Формирование сообщения об ошибке, содержащего конфиденциальную информацию

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
def divide_numbers(a, b):
    try:
        result = a / b
        return result
    except Exception as e:
        error_msg = f"An error occurred: {str(e)}"
        print(error_msg)
```


Код, не соответствующий требованиям, записывает сообщение об исключении в переменную error_msg и выводит его непосредственно на консоль. Это может привести к генерации сообщений об ошибках, содержащих конфиденциальную информацию, например данные о подключении к базе данных, трассировку стека или другую внутреннюю информацию системы. Если злоумышленнику удастся вызвать исключение, он сможет получить ценную информацию, которая может быть использована для дальнейшей эксплуатации системы.





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
import logging

def divide_numbers(a, b):
    try:
        result = a / b
        return result
    except Exception as e:
        logging.error("An error occurred during division", exc_info=True)
```

Код, соответствующий требованиям, решает эту проблему, используя для обработки сообщений об ошибках фреймворк протоколирования, например встроенный модуль протоколирования. Вместо того чтобы напрямую выводить сообщение об ошибке на консоль, код использует метод logging.error для записи сообщения об ошибке вместе с трассировкой стека (exc_info=True). Использование фреймворка протоколирования позволяет правильно обрабатывать и записывать сообщения об ошибках в соответствии с заданными настройками протоколирования. Это позволяет предотвратить раскрытие конфиденциальной информации в сообщениях об ошибках, выводимых конечным пользователям или злоумышленникам.






## Незащищенное хранение учетных данных

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
def save_credentials(username, password):
    credentials_file = open("credentials.txt", "w")
    credentials_file.write(f"Username: {username}\n")
    credentials_file.write(f"Password: {password}\n")
    credentials_file.close()
```

Несоответствующий требованиям код сохраняет предоставленные имя пользователя и пароль непосредственно в файл "credentials.txt" без какой-либо формы шифрования или защиты. Хранение такой конфиденциальной информации, как учетные данные, в виде обычного текста крайне небезопасно, поскольку любой человек, имеющий доступ к файлу, может легко прочитать и использовать информацию не по назначению. Это может привести к несанкционированному доступу и компрометации учетных записей пользователей.





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
import hashlib

def save_credentials(username, password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    credentials = f"Username: {username}\nPassword: {hashed_password}\n"
    
    with open("credentials.txt", "w") as credentials_file:
        credentials_file.write(credentials)
```

Соответствующий код решает эту проблему, используя алгоритм одностороннего хэширования (в данном примере SHA-256) для безопасного хэширования пароля перед его хранением. Пароль хранится не напрямую, а вычисляется и сохраняется его хэш-значение. Хеширование является односторонним процессом, что затрудняет получение исходного пароля из хэша. Благодаря использованию безопасной хэш-функции, даже если злоумышленник получит доступ к хранящимся учетным данным, он не сможет легко пересчитать исходный пароль. Это значительно повышает безопасность хранимых учетных данных.



## Trust Boundary Violation

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
import subprocess

def process_user_input(user_input):
    # Предположим, что user_input поступает из недоверенного источника
    cmd = f"echo '{user_input}'"
    output = subprocess.check_output(cmd, shell=True)
    print(output)
```

Несоответствующий код напрямую принимает пользовательский ввод и использует его для создания команды, которую должен выполнить модуль подпроцесса. Такой подход может привести к нарушению границ доверия, поскольку позволяет недоверенному вводу выполняться в качестве команды в системе. Злоумышленник может внедрить вредоносные команды, что приведет к несанкционированному доступу или выполнению произвольного кода в системе.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
import subprocess
import shlex

def process_user_input(user_input):
    # Предположим, что user_input поступает из недоверенного источника
    cmd_args = shlex.split(f"echo {user_input}")
    output = subprocess.check_output(cmd_args)
    print(output)
```


Соответствующий код устраняет нарушение границ доверия с помощью функции shlex.split() для правильной токенизации пользовательского ввода, обеспечивая его интерпретацию как отдельных аргументов, а не как одной команды. Это помогает предотвратить атаки внедрения команд, гарантируя, что вводимые данные рассматриваются как данные, а не как исполняемый код. Правильно обрабатывая и обеззараживая пользовательский ввод, код устанавливает четкую границу доверия и снижает риск несанкционированного выполнения команд.






## Недостаточно защищенные учетные данные

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
import requests

def login(username, password):
    # Предполагается, что имя пользователя и пароль поступают от пользователя
    url = "https://example.com/login"
    data = {"username": username, "password": password}
    response = requests.post(url, data=data)
    
    if response.status_code == 200:
        print("Login successful")
    else:
        print("Login failed")
```

Код, не отвечающий требованиям, принимает предоставленные пользователем значения имени пользователя и пароля и отправляет их в виде открытого текста в POST-запросе к конечной точке входа. Такой подход подвергает учетные данные потенциальному перехвату или подслушиванию, поскольку они передаются без какой-либо защиты. Злоумышленники могут перехватить сетевой трафик или журналы доступа, чтобы получить учетные данные, что поставит под угрозу безопасность учетной записи пользователя.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
import requests
from requests.auth import HTTPDigestAuth

def login(username, password):
    # Предполагается, что имя пользователя и пароль поступают от пользователя
    url = "https://example.com/login"
    auth = HTTPDigestAuth(username, password)
    response = requests.post(url, auth=auth)
    
    if response.status_code == 200:
        print("Login successful")
    else:
        print("Login failed")
```


Соответствующий код решает проблему недостаточно защищенных учетных данных, используя HTTP Digest Authentication (HTTPDigestAuth) для безопасной передачи имени пользователя и пароля. Дайджест-аутентификация использует механизм "вызов-ответ", который включает хэширование пароля и отправку хэшированного значения вместе с запросом. Такой подход гарантирует, что пароль не будет передан в открытом виде, что обеспечивает более высокий уровень защиты от атак подслушивания или перехвата.







## Ограничение ссылки на внешние сущности XML

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
import xml.etree.ElementTree as ET

def parse_xml(xml_string):
    tree = ET.fromstring(xml_string)
    # Обработка данных XML
    ...
```

Несоответствующий код использует модуль xml.etree.ElementTree для разбора XML-строки. Однако он явно не отключает разрешение внешних сущностей, что может привести к риску безопасности. Злоумышленник может создать вредоносный XML-файл, содержащий ссылки на внешние сущности, и использовать это для осуществления XXE-атак, таких как чтение конфиденциальных файлов или атаки типа "отказ в обслуживании".





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
import xml.etree.ElementTree as ET

def parse_xml(xml_string):
    parser = ET.XMLParser()
    parser.entity_declaration = False  # Отключить разрешение внешних сущностей
    tree = ET.fromstring(xml_string, parser=parser)
    # Обработка XML-данных
    ...
```


Соответствующий код явно создает парсер XML (ET.XMLParser()) и отключает разрешение внешних сущностей, устанавливая параметр parser.entity_declaration в значение False. Это гарантирует, что любые ссылки на внешние сущности в XML-строке не будут разрешены, что снижает риск XXE-атак. Отключая разрешение внешних сущностей, код ограничивает парсер от доступа к внешним сущностям или их включения, повышая безопасность обработки XML.





## Уязвимые и устаревшие компоненты


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
from flask import Flask, render_template
import requests

app = Flask(__name__)

@app.route('/')
def index():
    # Используйте уязвимую функцию для получения данных
    response = requests.get('http://example.com/api/v1/users')
    data = response.json()
    return render_template('index.html', data=data)

if __name__ == '__main__':
    app.run()
```

Несоответствующий код использует библиотеку requests для выполнения HTTP-запроса к конечной точке API и получения пользовательских данных. Однако в коде не учитываются последствия использования устаревших или уязвимых компонентов для безопасности. Использование устаревших библиотек может подвергнуть приложение известным уязвимостям безопасности, которые могут быть использованы злоумышленниками.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
from flask import Flask, render_template
import requests
from requests.packages.urllib3.util import ssl_

# Отключение предупреждений о проверке SSL
ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'

app = Flask(__name__)

@app.route('/')
def index():
    # Используйте безопасную функцию для получения данных
    response = requests.get('https://example.com/api/v1/users', verify=False)
    data = response.json()
    return render_template('index.html', data=data)

if __name__ == '__main__':
    app.run()
```


Соответствующий кодекс предпринимает дополнительные шаги для решения проблемы использования уязвимых и устаревших компонентов:

1. Он отключает предупреждения о проверке SSL с помощью переменной ssl_.DEFAULT_CIPHERS из requests.packages.urllib3.util. Это предотвращает предупреждения, связанные с проверкой SSL при выполнении HTTPS-запросов.
2. Для отключения проверки SSL-сертификата при выполнении запроса явно устанавливается значение verify=False. Это делается с осторожностью и должно использоваться только в том случае, если риски, связанные с небезопасными соединениями, адекватно снижены в конкретном контексте приложения.
3. Используется последняя версия библиотеки requests, чтобы воспользоваться последними исправлениями и улучшениями безопасности.

Решая эти проблемы, совместимый код предпринимает шаги по снижению риска, связанного с использованием уязвимых и устаревших компонентов, и повышает общую безопасность приложения. Важно регулярно обновлять зависимости и библиотеки, чтобы обеспечить использование последних безопасных версий.






## Неправильная проверка сертификата с несоответствием хоста

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
import requests

def get_secure_data(url):
    # Выполнение запроса без надлежащей проверки сертификата
    response = requests.get(url, verify=False)
    return response.text

# Пример использования
data = get_secure_data('https://example.com')
print(data)
```

Несоответствующий код использует библиотеку requests для выполнения HTTPS-запроса к указанному URL. Однако он отключает проверку сертификата, устанавливая значение verify=False при выполнении запроса. Это означает, что код не проверяет должным образом сертификат, предоставленный сервером, включая проверку на несоответствие хоста.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
import requests

def get_secure_data(url):
    # Выполните запрос с надлежащей проверкой сертификата
    response = requests.get(url)
    response.raise_for_status()  # Вызовите исключение, если запрос не прошел
    return response.text

# Пример использования
data = get_secure_data('https://example.com')
print(data)
```


Соответствующий код решает проблему неправильной проверки сертификата с несоответствием хоста, удаляя значение verify=False и позволяя библиотеке requests выполнять правильную проверку сертификата. Функция requests.get() по умолчанию выполняет проверку сертификата, гарантируя, что сертификат, представленный сервером, действителен и соответствует запрашиваемому хосту. Функция response.raise_for_status() также используется для создания исключения в случае неудачи запроса, что позволяет правильно обрабатывать ошибки.

Благодаря использованию правильной проверки сертификатов и проверки на несоответствие хостов, совместимый код повышает безопасность HTTPS-коммуникаций. Он гарантирует, что сертификат, представленный сервером, действителен и соответствует запрашиваемому хосту, что снижает риск атак типа "человек посередине" и несанкционированного доступа к конфиденциальной информации.







## Неправильная аутентификация

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
import requests

def login(username, password):
    credentials = {'username': username, 'password': password}
    response = requests.post('https://example.com/login', data=credentials)
    if response.status_code == 200:
        return 'Login successful'
    else:
        return 'Login failed'

# Пример использования
result = login('admin', 'password')
print(result)
```

Несоответствующий код использует механизм базовой аутентификации, при котором имя пользователя и пароль отправляются в виде обычного текста в теле запроса. Такой подход небезопасен, поскольку не обеспечивает должной защиты конфиденциальных данных во время передачи.







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
import requests
from requests.auth import HTTPBasicAuth

def login(username, password):
    credentials = HTTPBasicAuth(username, password)
    response = requests.post('https://example.com/login', auth=credentials)
    if response.status_code == 200:
        return 'Login successful'
    else:
        return 'Login failed'

# Пример использования
result = login('admin', 'password')
print(result)
```


Соответствующий код решает проблему неправильной аутентификации с помощью HTTP Basic Authentication. Он использует класс HTTPBasicAuth из модуля requests.auth для обеспечения правильного кодирования учетных данных в заголовке авторизации. Это гарантирует, что имя пользователя и пароль будут переданы безопасным способом, поскольку они кодируются в формате Base64.

Благодаря использованию надлежащих механизмов аутентификации, таких как HTTP Basic Authentication, совместимый код повышает безопасность процесса входа в систему. Он обеспечивает защиту конфиденциальных учетных данных во время передачи, снижая риск несанкционированного доступа или перехвата злоумышленниками.







## Фиксация сеанса

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
from flask import Flask, request, session

app = Flask(__name__)
app.secret_key = 'insecure_secret_key'

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # Аутентификация пользователя
    if username == 'admin' and password == 'password':
        session['username'] = username
        return 'Login successful'
    else:
        return 'Login failed'

@app.route('/profile')
def profile():
    if 'username' in session:
        return f"Welcome, {session['username']}!"
    else:
        return 'Please login'

# Пример использования
app.run()
```

Несоответствующий код использует веб-фреймворк Flask и сохраняет имя пользователя в сессии после успешного входа. Однако он не регенерирует идентификатор сессии при входе, что делает его уязвимым для атак с фиксацией сессии. Злоумышленник может получить действительный идентификатор сессии и навязать его жертве, что позволит ему перехватить ее сессию.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
from flask import Flask, request, session
import os

app = Flask(__name__)
app.secret_key = os.urandom(16)

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    # Аутентификация пользователя
    if username == 'admin' and password == 'password':
        session.regenerate()  # Регенерация идентификатора сеанса
        session['username'] = username
        return 'Login successful'
    else:
        return 'Login failed'

@app.route('/profile')
def profile():
    if 'username' in session:
        return f"Welcome, {session['username']}!"
    else:
        return 'Please login'

# Пример использования
app.run()
```


Соответствующий код устраняет уязвимость фиксации сеанса путем регенерации идентификатора сеанса при успешном входе в систему с помощью метода regenerate(), предоставляемого объектом session. Это гарантирует, что идентификатор сеанса будет изменен после аутентификации, что не позволит злоумышленнику зафиксировать идентификатор сеанса и перехватить сеанс пользователя.

Регенерируя идентификатор сеанса при входе в систему, совместимый код снижает риск атак с фиксацией сеанса. Он гарантирует, что каждый пользователь получит уникальный и непредсказуемый идентификатор сеанса, что повышает безопасность механизма управления сеансами.





## Включение функциональности из недоверенного управления

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
import requests

# Получение и выполнение кода из ненадежного источника
untrusted_code = requests.get('http://example.com/untrusted_code.py').text
exec(untrusted_code)
```

Несоответствующий код получает код из недоверенного источника с помощью библиотеки запросов и выполняет его с помощью функции exec(). Такой подход создает значительные риски для безопасности, поскольку недоверенный код может содержать вредоносные инструкции или выполнять несанкционированные действия в системе.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
import requests
import ast

# Получение и оценка кода из недоверенного источника
untrusted_code = requests.get('http://example.com/untrusted_code.py').text
ast.parse(untrusted_code)
```


Совместимый код использует более осторожный подход при включении функциональности из недоверенного элемента управления. Вместо непосредственного выполнения кода он использует функцию ast.parse() из модуля ast для разбора и оценки кода в виде абстрактного синтаксического дерева (AST). Это позволяет более безопасно анализировать код, не выполняя его напрямую.

Разбирая недоверенный код в виде AST, совместимый код получает возможность проверить и подтвердить структуру и содержимое кода, прежде чем принять решение о его выполнении. Это снижает риск выполнения произвольного или вредоносного кода, обеспечивая дополнительный уровень безопасности.





## Загрузка кода без проверки целостности

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
import requests

# Загрузите код без проверки целостности
code_url = 'http://example.com/malicious_code.py'
response = requests.get(code_url)
code = response.text

# Выполните загруженный код
exec(code)
```

Несоответствующий код напрямую загружает код из удаленного источника с помощью библиотеки запросов, не выполняя никакой проверки целостности. Затем он переходит к выполнению загруженного кода с помощью функции exec(). Такой подход может быть опасен, поскольку позволяет выполнить потенциально вредоносный или неавторизованный код без проверки его целостности.





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
import requests
import hashlib

# Загрузите код с проверкой целостности
code_url = 'http://example.com/malicious_code.py'
response = requests.get(code_url)
code = response.text

# Проверьте целостность кода
expected_hash = '4a2d8f37ac...'
calculated_hash = hashlib.sha256(code.encode()).hexdigest()
if calculated_hash == expected_hash:
    exec(code)
else:
    print("Integrity check failed. Code execution aborted.")
```


Совместимый код включает проверку целостности, чтобы убедиться в подлинности загруженного кода перед выполнением. Он вычисляет хэш загруженного кода с помощью криптографического алгоритма (в данном случае SHA-256) и сравнивает его с ожидаемым значением хэша. Если вычисленный хэш совпадает с ожидаемым хэшем, код считается валидным и может быть выполнен с помощью exec(). Если хэши не совпадают, выполнение кода прерывается, и на экран выводится соответствующее сообщение.

Проверяя целостность загруженного кода, совместимый код снижает риск выполнения поддельного или вредоносного кода, обеспечивая дополнительный уровень безопасности.






## Десериализация недоверенных данных

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
import pickle

def deserialize_data(data):
    # ПРЕДУПРЕЖДЕНИЕ: Этот код не соответствует требованиям и небезопасен
    obj = pickle.loads(data)
    return obj
```

Несоответствующий код использует функцию pickle.loads() для десериализации недоверенных данных без каких-либо мер безопасности. Такой подход очень уязвим для атак на десериализацию, таких как выполнение произвольного кода или внедрение вредоносных объектов. Злоумышленники могут создать вредоносную полезную нагрузку, чтобы использовать уязвимости в процессе десериализации и скомпрометировать систему.







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
import pickle

def deserialize_data(data):
    try:
        obj = pickle.loads(data)
        # Удостоверьте десериализованный объект или выполните дополнительные проверки безопасности
        # ...
        return obj
    except (pickle.UnpicklingError, AttributeError, ImportError, TypeError) as e:
        # Обработка ошибок десериализации
        # Занесите в журнал или вызовите исключение, или верните значение по умолчанию
        # ...
        return None
```


В совместимом коде реализованы меры безопасности для снижения рисков, связанных с десериализацией недоверенных данных. Он использует блок try-except для обработки потенциальных исключений во время десериализации. Это помогает предотвратить уязвимости выполнения кода и гарантирует, что приложение изящно справится с любыми ошибками.



Кроме того, в совместимом коде можно выполнить проверку достоверности и безопасности десериализованного объекта, чтобы убедиться, что он соответствует ожидаемым критериям. Это может включать проверку типа, структуры или специфических атрибутов объекта, в зависимости от контекста и требований вашего приложения.

Очень важно быть осторожным при десериализации недоверенных данных и рассмотреть дополнительные меры безопасности, такие как проверка ввода, проверка целостности данных и ограничение десериализации доверенными классами или модулями. Эти меры помогут защититься от уязвимостей десериализации и повысить общую безопасность вашего приложения.






## Недостаточное протоколирование

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
import logging

def process_data(data):
    # Обработка данных
    # ...
    
    # Записать результат в журнал
    logging.info("Data processed successfully")
```

В коде, не соответствующем требованиям, используется базовый оператор протоколирования без предоставления достаточной информации. Он просто записывает в журнал общее сообщение, указывающее на то, что данные были успешно обработаны. Такой подход не содержит важных деталей, что затрудняет диагностику проблем, мониторинг поведения приложения и расследование инцидентов безопасности. Недостаточное протоколирование затрудняет эффективное обнаружение и реагирование на нарушения безопасности и другие события.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
import logging

def process_data(data):
    # Обработка данных
    # ...
    
    # Зафиксируйте результат с дополнительной информацией
    logging.info("Data processed successfully: %s", data)
```


Соответствующий код улучшает протоколирование, включая дополнительную информацию в сообщение журнала. В этом примере обработанные данные включены в сообщение журнала с помощью форматирования строк. Благодаря добавлению соответствующих деталей, таких как обработанные данные или любая контекстная информация, журнал становится более информативным и помогает в поиске неисправностей, аудите и мониторинге.


Важно регистрировать значимые события, ошибки и информацию, связанную с безопасностью, во всех приложениях. Кроме того, уровни регистрации (например, info, warning, error) должны использоваться в зависимости от серьезности и значимости регистрируемого события.


Правильное ведение журнала облегчает обнаружение и анализ инцидентов безопасности, позволяет эффективно реагировать на них и дает ценные сведения о поведении приложения. Очень важно регистрировать достаточное количество информации, не забывая при этом о чувствительности данных и требованиях соответствия.





## Неправильная нейтрализация выхода для бревен

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
import logging

def log_user_input(username):
    # Зафиксируйте ввод данных пользователем
    logging.info("Received username: " + username)
```

Несоответствующий код напрямую объединяет вводимое пользователем имя пользователя со строкой сообщения журнала с помощью оператора +. Такой подход уязвим для инъекций в журнал, когда злоумышленник может манипулировать вводом, чтобы внедрить вредоносные символы или последовательности форматирования журнала. Это может привести к подделке журнала, атакам с инъекцией в журнал или даже к раскрытию конфиденциальной информации в записях журнала.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
import logging

def log_user_input(username):
    # Регистрация пользовательского ввода с надлежащей нейтрализацией вывода
    logging.info("Received username: %s", username)
```


Код, соответствующий требованиям, использует нейтрализацию вывода, применяя форматирование строк с заполнителями %s и передавая переменную username в качестве аргумента. Это гарантирует, что введенные пользователем данные будут рассматриваться как данные, а не как инструкции по форматированию. Благодаря нейтрализации вывода специальные символы или последовательности форматирования, введенные злоумышленником, становятся безвредными и записываются в журнал, как и предполагалось.


Правильная нейтрализация вывода помогает предотвратить атаки внедрения в журнал и гарантирует, что регистрируемая информация точно отражает предполагаемые данные, не нарушая целостности записей журнала.


Очень важно нейтрализовать управляемый пользователем ввод и другие динамические данные при включении их в сообщения журнала, чтобы предотвратить уязвимости в системе безопасности и сохранить целостность и конфиденциальность регистрируемой информации.







## Упущение информации, имеющей отношение к безопасности

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
def login(username, password):
    if username == "admin" and password == "password":
        print("Login successful")
    else:
        print("Login failed")
```


Несоответствующий код просто выводит общее сообщение об успешном или неудачном входе в систему, не предоставляя никаких конкретных сведений. Отсутствие важной для безопасности информации может затруднить диагностику и реагирование на потенциальные проблемы безопасности или атаки. В сообщении отсутствует необходимый контекст для понимания причины неудачи входа в систему, что может привести к раскрытию конфиденциальной информации или позволить злоумышленнику узнать действительные имена пользователей или пароли.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
import logging

def login(username, password):
    if username == "admin" and password == "password":
        logging.info("Successful login for user: %s", username)
    else:
        logging.warning("Failed login attempt for user: %s", username)
```


Код, соответствующий требованиям, улучшает подход к ведению журнала, предоставляя в сообщениях журнала информацию, имеющую отношение к безопасности. Он использует модуль протоколирования для записи подробностей попыток входа в систему. В случае успешного входа в систему в журнал записывается информационное сообщение об успешном входе в систему с указанием имени пользователя. В случае неудачной попытки входа в систему записывается предупреждающее сообщение о неудачной попытке и имя пользователя.


Благодаря включению в сообщения журнала информации, имеющей отношение к безопасности, становится проще отслеживать и анализировать действия по входу в систему, выявлять подозрительные попытки входа и расследовать потенциальные нарушения безопасности. Это помогает повысить уровень безопасности приложения и облегчает реагирование на инциденты и криминалистический анализ в случае возникновения каких-либо инцидентов безопасности.








## Помещение конфиденциальной информации в файл журнала

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
import logging

def process_payment(payment_data):
    logging.info("Payment processed for user: %s", payment_data['user'])
```

Код, не соответствующий требованиям, записывает конфиденциальную информацию, например имя пользователя, непосредственно в файл журнала с помощью функции logging.info(). Такая практика может привести к раскрытию конфиденциальных данных неавторизованным лицам, которые могут иметь доступ к файлам журнала. Хранение конфиденциальной информации в журналах в виде обычного текста представляет собой риск для безопасности и может привести к утечке данных или несанкционированному доступу.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
import logging

def process_payment(payment_data):
    logging.info("Payment processed for user: %s", obfuscate_user(payment_data['user']))

def obfuscate_user(user):
    # Код для обфускации или маскировки конфиденциальной информации
    return "****" + user[-4:]
```


Соответствующий код решает эту проблему путем обфускации или маскировки конфиденциальной информации перед ее записью в журнал. В этом примере функция obfuscate_user() используется для замены конфиденциальной информации о пользователе на замаскированные данные. Процесс обфускации может включать такие методы, как усечение, замена или шифрование, в зависимости от конкретных требований.


Обфусцируя конфиденциальную информацию перед записью в журнал, совместимый код предотвращает раскрытие реальных данных пользователя в файлах журнала. Это повышает безопасность и конфиденциальность пользовательской информации, гарантируя, что даже если к файлам журнала получат доступ неавторизованные лица, конфиденциальные данные останутся под защитой.

Важно отметить, что обфускация не является надежной мерой безопасности и не должна заменять собой надлежащие средства контроля доступа и защиты данных. Это лишь один из шагов в многоуровневом подходе к защите конфиденциальной информации.






## Подделка запросов со стороны сервера (SSRF)

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
import requests

def fetch_url(url):
    response = requests.get(url)
    return response.text
```

Несоответствующий код напрямую получает содержимое заданного URL с помощью функции requests.get(). Этот код уязвим для атак SSRF, поскольку позволяет выполнять произвольные запросы к любому URL, включая внутренние или ограниченные сетевые ресурсы. Злоумышленники могут использовать эту уязвимость для выполнения запросов к внутренним службам, получения конфиденциальной информации или проведения дальнейших атак на сервер.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
import requests

def fetch_url(url):
    if is_valid_url(url):
        response = requests.get(url)
        return response.text
    else:
        raise ValueError("Invalid URL")

def is_valid_url(url):
    # Выполните проверку URL-адресов, чтобы убедиться в безопасности доступа.
    # Внедрите проверку на основе белых списков или ограничьте доступ к определенным доменам.

    # Пример: Разрешить доступ к определенным доменам
    allowed_domains = ['example.com', 'api.example.com']
    parsed_url = urlparse(url)
    return parsed_url.netloc in allowed_domains
```

Соответствующий код включает этап проверки URL перед выполнением запроса. Он использует функцию is_valid_url() для проверки на основе белого списка или ограничений конкретного домена. Этап проверки гарантирует, что доступ будет осуществляться только к доверенным и разрешенным URL, что снижает риск атак SSRF.

Функция is_valid_url() является лишь примером реализации. Вы должны настроить логику проверки в соответствии с вашими требованиями и политиками безопасности. Реализация может включать такие проверки, как составление белых списков разрешенных доменов, применение строгой структуры URL или проверку по заранее определенному списку безопасных URL.

Проверяя URL перед отправкой запроса, совместимый код помогает предотвратить атаки SSRF, ограничивая доступ к известным, надежным и безопасным URL. Это помогает гарантировать, что приложение взаимодействует только с предназначенными ресурсами, и снижает риск несанкционированного доступа к внутренним или ограниченным сетевым ресурсам.

