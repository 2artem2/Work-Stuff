---
layout: default
title: NodeJS
parent: Rules
---

# NodeJS
{: .no_toc }


## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---





## Раскрытие конфиденциальной информации

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
const fs = require('fs');

function login(username, password) {
  // Проверьте имя пользователя и пароль
  if (username === 'admin' && password === 'password123') {
    // Зарегистрируйте успешный вход в систему
    fs.appendFileSync('logs.txt', `Successful login: ${username}`);
    return true;
  } else {
    // Зарегистрируйте неудачный вход в систему
    fs.appendFileSync('logs.txt', `Failed login: ${username}`);
    return false;
  }
}
```

В этом коде, не соответствующем требованиям, функция входа в систему записывает конфиденциальную информацию, например имя пользователя, непосредственно в файл журнала (logs.txt). Это представляет собой риск для безопасности, поскольку файл журнала может быть доступен неавторизованным пользователям, что может привести к раскрытию конфиденциальной информации, такой как имена пользователей или пароли.


Чтобы решить эту проблему, ниже приведен пример кода, который позволяет избежать раскрытия конфиденциальной информации в файле журнала:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
const fs = require('fs');

function login(username, password) {
  // Проверьте имя пользователя и пароль
  if (username === 'admin' && password === 'password123') {
    // Зафиксируйте успешный вход в систему без конфиденциальной информации
    fs.appendFileSync('logs.txt', 'Successful login');
    return true;
  } else {
    // Зафиксируйте неудачный вход в систему, не раскрывая конфиденциальной информации
    fs.appendFileSync('logs.txt', 'Failed login');
    return false;
  }
}
```


В этом совместимом коде конфиденциальная информация (имя пользователя) не записывается в журнал напрямую. Вместо этого в файл журнала записывается только общее сообщение об успешном или неудачном входе в систему. Избегая прямого раскрытия конфиденциальной информации в файле журнала, вы можете защитить учетные данные пользователей и предотвратить возможное неправомерное использование или несанкционированный доступ.

Кроме того, важно обеспечить надлежащую защиту самих файлов журнала и ограничить доступ к ним только для авторизованного персонала. Это может включать установку соответствующих разрешений на файлы, шифрование файлов журнала или использование централизованного решения для ведения журнала, которое предлагает надежные средства контроля доступа и безопасности.





## Вставка конфиденциальной информации в отправленные данные

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
const express = require('express');
const app = express();

app.get('/user', (req, res) => {
  const userId = req.query.id;
  const userData = getUserData(userId);

  // Включите в ответ конфиденциальную информацию
  res.json({
    id: userId,
    username: userData.username,
    email: userData.email,
    password: userData.password
  });
});

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
```

В этом несовместимом коде, когда конечная точка /user вызывается с параметром запроса id, она извлекает данные пользователя для указанного ID и включает конфиденциальную информацию, такую как пароль, в ответный JSON. Это может представлять угрозу безопасности, так как конфиденциальная информация может быть перехвачена или доступна неавторизованным лицам.


Чтобы решить эту проблему, приведем пример кода, который позволяет избежать вставки конфиденциальной информации в отправленные данные:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
const express = require('express');
const app = express();

app.get('/user', (req, res) => {
  const userId = req.query.id;
  const userData = getUserData(userId);

  // Исключите из ответа конфиденциальную информацию
  const { id, username, email } = userData;
  res.json({ id, username, email });
});

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
```


В этом совместимом коде в JSON-ответ включается только необходимая нечувствительная информация (например, идентификатор пользователя, имя пользователя и электронная почта). Конфиденциальная информация, например пароль, исключается из ответа, что снижает риск раскрытия конфиденциальных данных неавторизованным пользователям.

Важно обеспечить безопасное обращение с конфиденциальной информацией и ее передачу только авторизованным пользователям или в соответствующих контекстах. Следуя принципу наименьших привилегий и исключая конфиденциальные данные из отправляемых данных, вы можете снизить риск несанкционированного доступа или раскрытия конфиденциальной информации.






## Подделка межсайтовых запросов (CSRF)

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
const express = require('express');
const app = express();

app.get('/transfer-money', (req, res) => {
  const amount = req.query.amount;
  const toAccount = req.query.to;

  // Перевести деньги на указанный счет
  transferMoney(amount, toAccount);

  res.send('Money transferred successfully!');
});

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
```

В этом несоответствующем коде конечная точка /transfer-money позволяет перевести деньги, выполнив GET-запрос с параметрами запроса суммы и счета получателя. Такая конструкция уязвима для CSRF-атак, поскольку злоумышленник может создать вредоносный веб-сайт, который автоматически выполнит этот запрос от имени жертвы, посетившей сайт. В результате деньги жертвы могут быть переведены без ее согласия или ведома.



Чтобы решить эту проблему, вот пример совместимого кода, который реализует защиту от CSRF с помощью токенов:




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
const express = require('express');
const csrf = require('csurf');
const app = express();

// Включите промежуточное ПО для защиты от CSRF
const csrfProtection = csrf({ cookie: true });

// Сгенерируйте и отправьте CSRF-токен клиенту
app.get('/csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// Переводите деньги только для действительных запросов, защищенных CSRF.
app.post('/transfer-money', csrfProtection, (req, res) => {
  const amount = req.body.amount;
  const toAccount = req.body.to;

  // Переведите деньги на указанный счет
  transferMoney(amount, toAccount);

  res.send('Money transferred successfully!');
});

app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
```


В этом совместимом коде промежуточное ПО для защиты от CSRF (csurf) используется для генерации и проверки CSRF-токенов. Сначала добавляется отдельный маршрут (/csrf-token) для генерации и отправки CSRF-токена клиенту. Затем конечная точка /transfer-money модифицируется так, чтобы принимать только POST-запросы и включать промежуточное ПО для защиты от CSRF. Это гарантирует, что перевод денег может быть осуществлен только в том случае, если вместе с запросом предоставляется действительный токен CSRF.


Реализуя защиту от CSRF, совместимый код не позволяет неавторизованным лицам выполнять вредоносные действия, например, переводить деньги, через поддельные запросы. Использование CSRF-токенов помогает проверять подлинность запросов и защищает от CSRF-атак.







## Использование жесткого пароля

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
const bcrypt = require('bcrypt');
const saltRounds = 10;
const password = 'myHardcodedPassword';

bcrypt.hash(password, saltRounds, (err, hash) => {
  if (err) {
    console.error('Error hashing password:', err);
    return;
  }

  // Сохраните хэшированный пароль в базе данных
  storePasswordInDatabase(hash);
});
```

В этом коде, не соответствующем требованиям, переменная password содержит жестко закодированное значение пароля. Хранение паролей непосредственно в коде представляет собой значительный риск безопасности, поскольку если злоумышленник получит доступ к кодовой базе, он сразу же узнает пароль, что потенциально может скомпрометировать учетные записи пользователей или безопасность системы.


Чтобы решить эту проблему, ниже приведен пример совместимого кода, который позволяет избежать использования жестко закодированных паролей:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
const bcrypt = require('bcrypt');
const saltRounds = 10;

function hashPassword(password, callback) {
  bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) {
      console.error('Error hashing password:', err);
      return callback(err);
    }

    // Сохраните хэшированный пароль в базе данных
    storePasswordInDatabase(hash, callback);
  });
}

// Использование
const password = 'myPassword';
hashPassword(password, (err) => {
  if (err) {
    console.error('Failed to hash password:', err);
    return;
  }

  console.log('Password hashed and stored successfully');
});
```

В этом совместимом коде функция hashPassword принимает пароль в качестве параметра и генерирует защищенный хэш с помощью библиотеки bcrypt. Затем хэшированный пароль сохраняется в базе данных. Благодаря отделению пароля от кода и передаче его в качестве параметра, жестко закодированный пароль больше не присутствует в кодовой базе. Вместо этого пароль передается во время выполнения программы, что снижает риск несанкционированного доступа к конфиденциальной информации.

Благодаря отказу от использования жестко закодированных паролей совместимый код повышает безопасность приложения и снижает риск несанкционированного доступа к учетным записям пользователей или системным ресурсам.







## Сломанный или рискованный криптоалгоритм

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
const crypto = require('crypto');

function hashPassword(password) {
  const hash = crypto.createHash('md5').update(password).digest('hex');
  return hash;
}

// Использование
const password = 'myPassword';
const hashedPassword = hashPassword(password);
console.log('Hashed password:', hashedPassword);
```


В этом несовместимом коде функция crypto.createHash используется с алгоритмом MD5 для хэширования пароля. Однако MD5 считается небезопасным для хеширования паролей из-за его уязвимости к атакам на столкновения и доступности более быстрых вычислительных ресурсов. Для защиты учетных данных пользователей важно использовать более надежные и безопасные алгоритмы, такие как bcrypt или Argon2, для хэширования паролей.


Для решения этой проблемы здесь приведен пример кода, который использует библиотеку bcrypt для безопасного хэширования паролей:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
const bcrypt = require('bcrypt');
const saltRounds = 10;

function hashPassword(password, callback) {
  bcrypt.hash(password, saltRounds, (err, hash) => {
    if (err) {
      console.error('Error hashing password:', err);
      return callback(err);
    }
    return callback(null, hash);
  });
}

// Использование
const password = 'myPassword';
hashPassword(password, (err, hashedPassword) => {
  if (err) {
    console.error('Failed to hash password:', err);
    return;
  }

  console.log('Hashed password:', hashedPassword);
});
```

В этом совместимом коде для безопасного хэширования пароля используется библиотека bcrypt. Функция bcrypt.hash генерирует соленый хэш с заданным количеством раундов, обеспечивая высокий уровень защиты от атак перебором и по словарю.

Благодаря использованию bcrypt вместо небезопасного алгоритма MD5 совместимый код значительно повышает безопасность хэширования паролей в приложении. Это помогает защитить учетные данные пользователей и не позволяет злоумышленникам легко получить оригинальные пароли с помощью перебора или атак по радужным таблицам.







## Недостаточная энтропия

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
function generateApiKey() {
  const length = 32;
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let apiKey = '';

  for (let i = 0; i < length; i++) {
    const randomIndex = Math.floor(Math.random() * chars.length);
    apiKey += chars.charAt(randomIndex);
  }

  return apiKey;
}

// Использование
const apiKey = generateApiKey();
console.log('Generated API key:', apiKey);
```


В этом несоответствующем коде функция generateApiKey пытается сгенерировать случайный ключ API путем выбора случайных символов из заранее определенного набора символов. Однако случайные значения генерируются с помощью функции Math.random(), которая может не обеспечивать достаточную энтропию для безопасной генерации случайных чисел. Функция Math.random() полагается на базовый генератор случайных чисел среды выполнения JavaScript, который может не подходить для криптографических целей.

Чтобы решить эту проблему, приведем пример кода, который использует модуль crypto в Node.js для генерации безопасного случайного API-ключа:







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
const crypto = require('crypto');

function generateApiKey() {
  const length = 32;
  const buffer = crypto.randomBytes(length);
  const apiKey = buffer.toString('hex');
  return apiKey;
}

// Использование
const apiKey = generateApiKey();
console.log('Generated API key:', apiKey);
```

В этом совместимом коде функция crypto.randomBytes из модуля crypto используется для генерации буфера криптографически безопасных случайных байтов. Затем этот буфер преобразуется в шестнадцатеричное строковое представление с помощью метода toString. Такой подход обеспечивает генерацию случайных значений с достаточной энтропией для безопасных целей.

Используя функцию crypto.randomBytes вместо Math.random(), совместимый код повышает энтропию генерируемого API-ключа, делая его более безопасным и устойчивым к атакам предсказания или угадывания.







## Межсайтовый скриптинг (XSS)

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
const express = require('express');
const app = express();

app.get('/search', (req, res) => {
  const query = req.query.q;
  const response = `Search results for: ${query}`;
  res.send(response);
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

В этом несоответствующем коде конечная точка /search извлекает поисковый запрос из параметров запроса (req.query.q) и включает его непосредственно в ответ без какой-либо санации или проверки. Это может привести к XSS-уязвимости, поскольку злоумышленник может создать вредоносный запрос, содержащий JavaScript-код, который будет выполнен при отображении ответа в браузере пользователя.


Чтобы решить эту проблему, приведем пример кода, который правильно санирует пользовательский ввод для предотвращения XSS-атак:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
const express = require('express');
const app = express();
const xss = require('xss');

app.get('/search', (req, res) => {
  const query = req.query.q;
  const sanitizedQuery = xss(query);
  const response = `Search results for: ${sanitizedQuery}`;
  res.send(response);
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```


В этом совместимом коде библиотека xss используется для дезинфекции пользовательского ввода (запроса) перед включением его в ответ. Функция xss экранирует любые HTML-теги и специальные символы в запросе, предотвращая их интерпретацию как кода при отображении в браузере. Это обеспечивает безопасность ответа от XSS-атак, эффективно нейтрализуя любой потенциально вредоносный ввод.

Благодаря надлежащей санации ввода с помощью такой библиотеки, как xss, совместимый код снижает риск возникновения XSS-уязвимостей и гарантирует, что пользовательский ввод будет правильно обработан и безопасно отображен в браузере.








## SQL-инъекция

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
const express = require('express');
const app = express();
const mysql = require('mysql');

app.get('/users', (req, res) => {
  const userId = req.query.id;
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  
  // Выполните SQL-запрос и верните результаты
  const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'password',
    database: 'mydb'
  });
  
  connection.query(query, (error, results) => {
    if (error) throw error;
    res.json(results);
  });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

В этом коде, не соответствующем требованиям, конечная точка /users извлекает идентификатор пользователя из параметров запроса (req.query.id) и напрямую интерполирует его в SQL-запрос (SELECT * FROM users WHERE id = ${userId}). Это делает код уязвимым для атак SQL-инъекций. Злоумышленник может манипулировать параметром userId и внедрить вредоносный SQL-код, потенциально получив несанкционированный доступ к базе данных или выполнив другие вредоносные действия.


Чтобы решить эту проблему, ниже приведен пример совместимого кода, в котором используются подготовленные операторы для устранения уязвимости SQL-инъекций:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
const express = require('express');
const app = express();
const mysql = require('mysql');

app.get('/users', (req, res) => {
  const userId = req.query.id;
  const query = 'SELECT * FROM users WHERE id = ?';
  const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'password',
    database: 'mydb'
  });

  connection.query(query, [userId], (error, results) => {
    if (error) throw error;
    res.json(results);
  });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

В этом коде, соответствующем требованиям, используется подготовленный оператор, в котором пользовательский ввод заменяется на заполнитель (?) в SQL-запросе (SELECT * FROM users WHERE id = ?). Фактический пользовательский ввод (userId) передается в качестве параметра в метод connection.query, что обеспечивает его правильное экранирование и обработку как значения, а не выполнение как части самого SQL-запроса. Это эффективно предотвращает атаки SQL-инъекций, отделяя код SQL от пользовательского ввода.

При использовании подготовленных операторов или параметризованных запросов совместимый код обеспечивает безопасную обработку пользовательского ввода и предотвращает вредоносные атаки SQL-инъекций, рассматривая пользовательский ввод как данные, а не как исполняемый код.





## Внешнее управление именем или путем файла

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
const express = require('express');
const app = express();
const fs = require('fs');

app.get('/download', (req, res) => {
  const fileName = req.query.file;
  const filePath = `/path/to/files/${fileName}`;

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.status(404).send('File not found');
    } else {
      res.setHeader('Content-Disposition', `attachment; filename=${fileName}`);
      res.send(data);
    }
  });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```


В этом несоответствующем коде конечная точка /download позволяет пользователям указывать имя файла в параметре запроса (req.query.file). Код напрямую использует имя файла, указанное пользователем, для построения пути к файлу (/path/to/files/${fileName}) и пытается прочитать и отправить содержимое файла. Такой подход приводит к уязвимости безопасности, известной как внешний контроль имени файла или пути, когда злоумышленник может манипулировать параметром файла для доступа к произвольным файлам в файловой системе сервера.


Чтобы решить эту проблему, приведем пример кода, который проверяет и санирует имя файла, чтобы предотвратить атаки с внешним контролем имени файла или пути:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
const express = require('express');
const app = express();
const fs = require('fs');
const path = require('path');

app.get('/download', (req, res) => {
  const fileName = req.query.file;
  const sanitizedFileName = path.basename(fileName); // Дезинфекция имени файла
  const filePath = path.join('/path/to/files', sanitizedFileName);

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.status(404).send('File not found');
    } else {
      res.setHeader('Content-Disposition', `attachment; filename=${sanitizedFileName}`);
      res.send(data);
    }
  });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

В этом совместимом коде имя файла, полученное из пользовательского ввода (req.query.file), дезинфицируется с помощью path.basename, чтобы извлечь имя файла и отбросить любую информацию о каталоге или попытки обхода пути. Затем дезинфицированное имя файла надежно соединяется с путем к базовому каталогу с помощью path.join, чтобы обеспечить построение корректного и безопасного пути к файлу. Проверяя и санируя имя файла, совместимый код предотвращает внешнее управление именем файла или атаки на путь и ограничивает доступ к файлу только целевым каталогом.

Важно отметить, что приведенные примеры кода предполагают упрощенный сценарий в демонстрационных целях. На практике для повышения безопасности загрузки файлов рекомендуется применять дополнительные меры безопасности, такие как контроль доступа, проверка типа файла и правильная обработка ошибок.






## Формирование сообщения об ошибке, содержащего конфиденциальную информацию

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
const express = require('express');
const app = express();

app.get('/user/:id', (req, res) => {
  const userId = req.params.id;
  const user = getUserFromDatabase(userId);

  if (!user) {
    throw new Error(`User ${userId} not found`); // Несоответствие требованиям: Сообщение об ошибке содержит конфиденциальную информацию
  }

  res.send(user);
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```


В этом несоответствующем коде, когда пользователь не найден в базе данных, возникает ошибка с сообщением об ошибке, включающим идентификатор пользователя (User ${userId} not found). Такой подход представляет собой угрозу безопасности, так как раскрывает конфиденциальную информацию (идентификатор пользователя) потенциальным злоумышленникам. Сообщения об ошибках, содержащие конфиденциальную информацию, могут быть использованы злоумышленниками для сбора информации о системе и потенциального проведения дальнейших атак.


Чтобы решить эту проблему, приведем пример кода, который позволяет избежать включения конфиденциальной информации в сообщения об ошибках:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
const express = require('express');
const app = express();

app.get('/user/:id', (req, res) => {
  const userId = req.params.id;
  const user = getUserFromDatabase(userId);

  if (!user) {
    res.status(404).send('User not found'); // Соответствует требованиям: Общее сообщение об ошибке без конфиденциальной информации
    return;
  }

  res.send(user);
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

В этом совместимом коде, когда пользователь не найден, отправляется общее сообщение об ошибке, не содержащее никакой конфиденциальной информации. Предоставляя общее сообщение об ошибке, код избегает утечки потенциально чувствительных данных и предоставляет ограниченную информацию потенциальным злоумышленникам.

Очень важно внимательно относиться к ошибкам и не раскрывать конфиденциальную информацию через сообщения об ошибках. Кроме того, рекомендуется регистрировать ошибки на стороне сервера для целей отладки и мониторинга, при этом необходимо следить за тем, чтобы в журналах не содержалось конфиденциальной информации.






## Незащищенное хранение учетных данных

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
const express = require('express');
const app = express();

let databaseCredentials = {
  username: 'admin',
  password: 'secretpassword'
};

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (username === databaseCredentials.username && password === databaseCredentials.password) {
    res.send('Login successful');
  } else {
    res.send('Invalid credentials');
  }
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

В этом несоответствующем коде учетные данные базы данных (имя пользователя и пароль) хранятся непосредственно в переменной (databaseCredentials) без какой-либо защиты. Хранение учетных данных открытым текстом в исходном коде или конфигурационных файлах крайне небезопасно и подвергает их потенциальному несанкционированному доступу. Любой человек, имеющий доступ к кодовой базе, может легко получить учетные данные, что представляет собой значительный риск для безопасности.


Чтобы решить эту проблему, мы приводим пример совместимого кода, который демонстрирует лучший подход к работе с учетными данными:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
const express = require('express');
const app = express();

// Эти учетные данные должны храниться в безопасном месте,
// например в переменных окружения или отдельном конфигурационном файле.
const databaseCredentials = {
  username: process.env.DB_USERNAME,
  password: process.env.DB_PASSWORD
};

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (username === databaseCredentials.username && password === databaseCredentials.password) {
    res.send('Login successful');
  } else {
    res.send('Invalid credentials');
  }
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

В совместимом коде учетные данные загружаются из переменных окружения (process.env), а не вводятся непосредственно в код. Хранение конфиденциальной информации, такой как учетные данные базы данных, в переменных окружения обеспечивает дополнительный уровень безопасности. Благодаря использованию переменных окружения учетные данные хранятся отдельно от кодовой базы и могут легко управляться и защищаться безопасным способом.


Не забудьте безопасно настроить переменные среды на сервере, где размещено приложение, чтобы обеспечить надлежащую защиту учетных данных.




## Нарушение границ доверия

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
const express = require('express');
const app = express();

app.post('/submitForm', (req, res) => {
  const isAdmin = req.body.isAdmin;

  if (isAdmin) {
    // Выполните привилегированную операцию
    grantAdminAccess();
  } else {
    // Обработка запроса пользователя
    processUserRequest();
  }

  res.send('Form submitted successfully');
});

function grantAdminAccess() {
  // Код для предоставления администраторского доступа
  // ...
}

function processUserRequest() {
  // Код для обработки запроса пользователя
  // ...
}

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

В этом несовместимом коде нет надлежащей проверки или соблюдения границы доверия между пользовательским вводом и привилегированными операциями. Код слепо доверяет значению req.body.isAdmin, чтобы определить, следует ли предоставить пользователю доступ администратора или нет. Такое нарушение границы доверия позволяет злоумышленнику манипулировать значением isAdmin и получить несанкционированные привилегии администратора.


Чтобы решить эту проблему, приведем пример кода, который демонстрирует правильное соблюдение границ доверия:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
const express = require('express');
const app = express();

app.post('/submitForm', (req, res) => {
  const isAdmin = Boolean(req.body.isAdmin);

  if (isAdmin) {
    // Проверьте аутентификацию и авторизацию пользователей перед предоставлением доступа администратора
    authenticateAndAuthorizeUser(req)
      .then(() => {
        grantAdminAccess();
        res.send('Admin access granted');
      })
      .catch(() => {
        res.status(403).send('Access denied');
      });
  } else {
    // Обработка запроса пользователя
    processUserRequest();
    res.send('Form submitted successfully');
  }
});

function grantAdminAccess() {
  // Код для предоставления доступа администратора
  // ...
}

function processUserRequest() {
  // Код для обработки запроса пользователя
  // ...
}

function authenticateAndAuthorizeUser(req) {
  // Выполните аутентификацию и авторизацию пользователей
  // ...
  // Возвращаем обещание, которое разрешается, если пользователь прошел аутентификацию и авторизацию, или отклоняется в противном случае
}

app.listen(3000, () => {
  console.log('Server started on port 3000');
});

```

В коде, соответствующем требованиям, значение req.body.isAdmin правильно проверяется и преобразуется в булево значение с помощью Boolean(req.body.isAdmin). Кроме того, код обеспечивает границу доверия, явно проверяя аутентификацию и авторизацию пользователя перед предоставлением администраторского доступа. Функция authenticateAndAuthorizeUser отвечает за выполнение необходимых проверок аутентификации и авторизации и возвращает обещание, которое разрешается, если пользователь аутентифицирован и авторизован, или отклоняется в противном случае.


Благодаря соблюдению границ доверия и надлежащей проверке вводимых пользователем данных код снижает риск несанкционированного доступа и гарантирует, что привилегированные операции будут выполняться только при наличии соответствующей аутентификации и авторизации.




## Недостаточно защищенные учетные данные

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
const express = require('express');
const app = express();

app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  // Храним учетные данные в виде обычного текста
  storeCredentials(username, password);

  // Выполняем аутентификацию
  const isAuthenticated = authenticate(username, password);

  if (isAuthenticated) {
    res.send('Login successful');
  } else {
    res.send('Login failed');
  }
});

function storeCredentials(username, password) {
  // Код для хранения учетных данных (не соответствует требованиям)
  // ...
}

function authenticate(username, password) {
  // Код для аутентификации пользователя
  // ...
}

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

В этом коде, не соответствующем требованиям, учетные данные пользователя хранятся в виде обычного текста при вызове функции storeCredentials. Хранение конфиденциальной информации, такой как пароли, в открытом тексте делает ее уязвимой для несанкционированного доступа в случае взлома системы.


Чтобы решить эту проблему, приведем пример кода, отвечающего требованиям, который демонстрирует надлежащую защиту учетных данных с помощью безопасного алгоритма хеширования:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
const express = require('express');
const bcrypt = require('bcrypt');
const app = express();

const saltRounds = 10;

app.post('/login', async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  // Хеширование пароля
  const hashedPassword = await hashPassword(password);

  // Сохраняем хэшированный пароль
  storeCredentials(username, hashedPassword);

  // Выполняем аутентификацию
  const isAuthenticated = await authenticate(username, password);

  if (isAuthenticated) {
    res.send('Login successful');
  } else {
    res.send('Login failed');
  }
});

async function hashPassword(password) {
  // Хеширование пароля с помощью bcrypt
  const salt = await bcrypt.genSalt(saltRounds);
  const hashedPassword = await bcrypt.hash(password, salt);
  return hashedPassword;
}

function storeCredentials(username, hashedPassword) {
  // Код для хранения хэшированных учетных данных
  // ...
}

async function authenticate(username, password) {
  // Получите хэшированный пароль из хранилища
  const storedHashedPassword = await getHashedPassword(username);

  // Сравните введенный пароль с сохраненным хэшированным паролем
  const isAuthenticated = await bcrypt.compare(password, storedHashedPassword);
  return isAuthenticated;
}

async function getHashedPassword(username) {
  // Код для получения хэшированного пароля из хранилища
  // ...
}

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```


В совместимом коде пароль пользователя защищен с помощью библиотеки bcrypt для безопасного хэширования пароля перед его сохранением. Функция hashPassword генерирует соль и хэширует пароль с помощью bcrypt. Полученный хэшированный пароль сохраняется с помощью функции storeCredentials.

Во время аутентификации сохраненный хэшированный пароль извлекается с помощью функции getHashedPassword. Введенный пароль сравнивается с сохраненным хэшированным паролем с помощью функции bcrypt.compare, которая выполняет безопасное сравнение без раскрытия исходного пароля.

Благодаря правильной защите учетных данных с помощью надежного алгоритма хеширования, такого как bcrypt, код гарантирует, что даже если хранящиеся пароли будут скомпрометированы, злоумышленник не сможет их легко прочитать или использовать.




## Ограничение ссылок на внешние сущности XML

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const xml2js = require('xml2js');

app.use(bodyParser.text({ type: 'text/xml' }));

app.post('/parse-xml', (req, res) => {
  const xmlData = req.body;

  // Разбор XML-данных
  xml2js.parseString(xmlData, (err, result) => {
    if (err) {
      res.status(400).send('Invalid XML data');
    } else {
      // Обработка XML-данных
      // ...
      res.send('XML data processed successfully');
    }
  });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

В этом несовместимом коде XML-данные, полученные от клиента, анализируются с помощью библиотеки xml2js без надлежащего ограничения ссылок на внешние сущности XML. Это может привести к XXE-атакам, когда злоумышленник может включить внешние сущности и прочитать произвольные файлы с сервера или выполнить другие вредоносные действия.


Для решения этой проблемы здесь приведен пример кода, демонстрирующий ограничение ссылок на внешние сущности XML:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const xml2js = require('xml2js');

app.use(bodyParser.text({ type: 'text/xml' }));

app.post('/parse-xml', (req, res) => {
  const xmlData = req.body;

  // Настройте парсер XML, чтобы отключить ссылки на внешние сущности
  const parser = new xml2js.Parser({
    explicitCharkey: true,
    explicitRoot: false,
    explicitArray: false,
    ignoreAttrs: true,
    mergeAttrs: false,
    xmlns: false,
    allowDtd: false,
    allowXmlExternalEntities: false, // Отключите ссылки на внешние сущности
  });

  // Разбор XML-данных
  parser.parseString(xmlData, (err, result) => {
    if (err) {
      res.status(400).send('Invalid XML data');
    } else {
      // Обработка XML-данных
      // ...
      res.send('XML data processed successfully');
    }
  });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```


В совместимом коде парсер XML из библиотеки xml2js настроен с параметром allowXmlExternalEntities, установленным в false, что запрещает ссылки на внешние сущности. Это предотвращает потенциальные XXE-атаки за счет запрета разбора внешних сущностей и гарантирует, что обрабатываются только безопасные XML-данные.

Ограничивая ссылки на внешние сущности XML, код снижает риск XXE-атак и помогает поддерживать целостность и безопасность приложения.




## Уязвимые и устаревшие компоненты


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const mongo = require('mongo');

app.use(bodyParser.json());

app.post('/user', (req, res) => {
  const user = req.body;
  mongo.connect('mongodb://localhost:27017', (err, client) => {
    if (err) {
      res.status(500).send('Internal Server Error');
    } else {
      const db = client.db('myapp');
      db.collection('users').insertOne(user, (err, result) => {
        if (err) {
          res.status(500).send('Internal Server Error');
        } else {
          res.status(200).send('User created successfully');
        }
      });
    }
  });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

В этом несоответствующем коде есть две проблемы, связанные с уязвимыми и устаревшими компонентами:

1. Пакет mongo используется для подключения к базе данных MongoDB. Однако версия используемого пакета может иметь известные уязвимости или быть устаревшей. Это может подвергнуть приложение потенциальным рискам безопасности.

2. Код не обрабатывает сценарии ошибок должным образом. В случае ошибки при подключении к базе данных или вводе пользователя приложение просто выдает сообщение "Внутренняя ошибка сервера". Отсутствие детальной обработки ошибок может затруднить выявление и устранение проблем безопасности или потенциальных уязвимостей.



Чтобы решить эти проблемы, приведем пример кода, который демонстрирует использование безопасных и современных компонентов, а также улучшенную обработку ошибок:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const MongoClient = require('mongodb').MongoClient;

app.use(bodyParser.json());

app.post('/user', (req, res) => {
  const user = req.body;
  MongoClient.connect('mongodb://localhost:27017', { useUnifiedTopology: true }, (err, client) => {
    if (err) {
      console.error(err);
      res.status(500).send('Database connection error');
    } else {
      const db = client.db('myapp');
      db.collection('users').insertOne(user, (err, result) => {
        if (err) {
          console.error(err);
          res.status(500).send('User creation error');
        } else {
          res.status(200).send('User created successfully');
        }
        client.close(); // Закройте соединение с базой данных
      });
    }
  });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```


В кодексе, соответствующем требованиям, были сделаны следующие улучшения:

1. Пакет mongo был заменен на пакет mongodb, который активно поддерживается и обновляется.

2. В соединение MongoClient добавлена опция useUnifiedTopology для обеспечения безопасной и рекомендуемой топологии соединения.

3. Реализована детальная обработка ошибок путем записи сообщений об ошибках в консоль. Это обеспечивает лучшую видимость потенциальных проблем и помогает в их устранении.

4. Метод client.close() вызывается для закрытия соединения с базой данных после завершения операции. Это помогает предотвратить утечку ресурсов и обеспечивает надлежащее управление соединением с базой данных.

Благодаря использованию безопасных и современных компонентов, а также улучшенным методам обработки ошибок, совместимый код снижает риск возникновения уязвимостей и обеспечивает более надежное и безопасное приложение.





## Неправильная проверка сертификата с несоответствием хоста

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
const https = require('https');

const options = {
  hostname: 'example.com',
  port: 443,
  path: '/',
  method: 'GET',
  rejectUnauthorized: false, // Отключение проверки сертификатов
};

const req = https.request(options, (res) => {
  res.on('data', (data) => {
    console.log(data.toString());
  });
});

req.end();
```

В этом несоответствующем коде параметр rejectUnauthorized установлен в false, что фактически отключает проверку сертификата. Это означает, что приложение Node.js примет любой сертификат, даже если он не соответствует ожидаемому имени хоста (в данном случае example.com). Это может привести к уязвимостям в безопасности, таким как атаки типа "человек посередине" или подмена.


Чтобы решить эту проблему, вот пример кода, который демонстрирует правильную проверку сертификата на соответствие ожидаемому имени хоста:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
const https = require('https');
const tls = require('tls');

const options = {
  hostname: 'example.com',
  port: 443,
  path: '/',
  method: 'GET',
  checkServerIdentity: (host, cert) => {
    const err = tls.checkServerIdentity(host, cert);
    if (err) {
      throw err; // Прервать соединение при несоответствии сертификата
    }
  },
};

const req = https.request(options, (res) => {
  res.on('data', (data) => {
    console.log(data.toString());
  });
});

req.end();
```


В совместимом коде опция checkServerIdentity используется для предоставления пользовательской функции обратного вызова, которая выполняет надлежащую проверку сертификата. Функция tls.checkServerIdentity используется для сравнения ожидаемого имени хоста (example.com) с общим именем (CN) или альтернативными именами субъектов (SAN) сертификата. Если обнаружено несоответствие, выдается ошибка, прерывающая соединение.

Благодаря надлежащей проверке сертификатов совместимый код гарантирует, что сертификат, представленный сервером, соответствует ожидаемому имени хоста, что снижает риск атак типа "человек посередине" и обеспечивает более безопасный канал связи.







## Неправильная аутентификация

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
const express = require('express');
const app = express();

app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  if (username === 'admin' && password === 'admin123') {
    // Успешная аутентификация
    res.send('Login successful!');
  } else {
    // Неудачная аутентификация
    res.send('Invalid username or password!');
  }
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

В этом несоответствующем коде механизм аутентификации основан на простой проверке имени пользователя и пароля. Имя пользователя и пароль получаются из тела запроса, и для определения успешности аутентификации выполняется жестко закодированное сравнение. Такой подход небезопасен, поскольку в нем отсутствуют надлежащие меры безопасности, такие как хэширование и соление паролей, применение надежных протоколов аутентификации и защита от атак методом перебора.


Чтобы решить эту проблему, мы приводим пример кода, который демонстрирует улучшенные методы аутентификации:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
const express = require('express');
const app = express();
const bcrypt = require('bcrypt');

// Имитация пользовательских данных
const users = [
  {
    username: 'admin',
    password: '$2b$10$rZrVJnI1.Y9OyK6ZrLqmguXHBXYTNcIQ00CJQc8XU1gYRGmdxcqzK', // Хешированный
                                                                              // пароль: "admin123"
  },
];

app.use(express.json());

app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  const user = users.find((user) => user.username === username);
  if (!user) {
    // Пользователь не найден
    return res.status(401).send('Invalid username or password!');
  }

  bcrypt.compare(password, user.password, (err, result) => {
    if (err) {
      // Ошибка при сравнении паролей
      return res.status(500).send('Internal Server Error');
    }

    if (result) {
      // Успешная аутентификация
      res.send('Login successful!');
    } else {
      // Неудачная аутентификация
      res.status(401).send('Invalid username or password!');
    }
  });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```


В совместимом коде процесс аутентификации несколько усовершенствован. Вместо простого сравнения в коде используется библиотека bcrypt для хэширования и безопасного сравнения паролей. Пароль пользователя хранится в виде хэшированного значения в пользовательских данных. Когда поступает запрос на вход в систему, код извлекает пользователя из данных пользователя на основе предоставленного имени пользователя. Затем используется bcrypt.compare для сравнения предоставленного пароля с сохраненным хэшированным паролем.

Реализуя правильное хеширование паролей и безопасное сравнение, совместимый код повышает безопасность процесса аутентификации, делая его более устойчивым к попыткам взлома паролей и повышая общую безопасность приложения.







## Фиксация сеанса

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
const express = require('express');
const session = require('express-session');
const app = express();

app.use(
  session({
    secret: 'insecuresecret',
    resave: false,
    saveUninitialized: true,
  })
);

app.get('/login', (req, res) => {
  // Сгенерируйте новый идентификатор сессии и сохраните его в куки сессии
  req.session.regenerate(() => {
    req.session.userId = 'admin';
    res.send('Logged in!');
  });
});

app.get('/profile', (req, res) => {
  // Доступ к профилю без аутентификации
  const userId = req.session.userId;
  if (userId) {
    res.send(`Welcome, ${userId}!`);
  } else {
    res.send('Please log in!');
  }
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

В этом несовместимом коде приложение использует промежуточное ПО express-session для управления сеансами. Однако оно уязвимо для атак с фиксацией сеанса. Код генерирует новый идентификатор сессии при посещении маршрута /login, но не аннулирует существующий идентификатор сессии. Это позволяет злоумышленнику зафиксировать идентификатор сессии, инициировав сеанс, а затем обманом заставить жертву использовать тот же самый идентификатор.


Чтобы решить эту проблему, приведем пример кода, демонстрирующий предотвращение фиксации сеанса:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const app = express();

app.use(
  session({
    secret: 'securesecret',
    resave: false,
    saveUninitialized: true,
    genid: () => {
      // Создайте уникальный идентификатор сессии
      return crypto.randomBytes(16).toString('hex');
    },
  })
);

app.get('/login', (req, res) => {
  // Регенерация идентификатора сеанса для предотвращения фиксации сеанса
  req.session.regenerate(() => {
    req.session.userId = 'admin';
    res.send('Logged in!');
  });
});

app.get('/profile', (req, res) => {
  // Доступ к профилю без аутентификации
  const userId = req.session.userId;
  if (userId) {
    res.send(`Welcome, ${userId}!`);
  } else {
    res.send('Please log in!');
  }
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```


В совместимом коде идентификатор сессии генерируется при успешном входе в систему с помощью метода regenerate, предоставляемого промежуточным ПО express-session. При этом предыдущий идентификатор сессии аннулируется и генерируется новый, уникальный. Таким образом, код предотвращает атаки с фиксацией сеанса, поскольку фиксированный идентификатор сеанса злоумышленника становится недействительным.

Реализовав регенерацию идентификатора сеанса и обеспечив выдачу нового идентификатора сеанса при входе в систему, совместимый код устраняет уязвимость фиксации сеанса и повышает общую безопасность приложения.





## Включение функциональности из недоверенного управления

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
const express = require('express');
const app = express();

app.get('/dynamic', (req, res) => {
  const functionName = req.query.function;

  // Выполнение указанной функции из недоверенного пользовательского ввода
  eval(functionName);
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

В этом коде, не соответствующем требованиям, приложение открывает конечную точку /dynamic, которая принимает параметр запроса функции. Код использует функцию eval() для прямого выполнения указанной функции из недоверенного пользовательского ввода. Такой подход очень опасен, поскольку позволяет выполнить произвольный код, что дает злоумышленникам возможность выполнить вредоносный код на сервере.


Для решения этой проблемы приведен пример совместимого кода, который позволяет избежать включения функциональности из недоверенных элементов управления:







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
const express = require('express');
const app = express();

app.get('/dynamic', (req, res) => {
  const functionName = req.query.function;

  // Проверьте имя функции на соответствие белому списку
  if (isFunctionAllowed(functionName)) {
    // Вызов разрешенной функции из предопределенного набора
    const result = callAllowedFunction(functionName);
    res.send(result);
  } else {
    res.status(400).send('Invalid function');
  }
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});

function isFunctionAllowed(functionName) {
  // Проверьте, входит ли имя функции в разрешенный набор
  const allowedFunctions = ['function1', 'function2', 'function3'];
  return allowedFunctions.includes(functionName);
}

function callAllowedFunction(functionName) {
  // Реализуйте логику для каждой разрешенной функции
  if (functionName === 'function1') {
    return 'Function 1 called';
  } else if (functionName === 'function2') {
    return 'Function 2 called';
  } else if (functionName === 'function3') {
    return 'Function 3 called';
  }
}
```


В совместимом коде приложение проверяет параметр запроса функции на соответствие белому списку разрешенных функций с помощью функции isFunctionAllowed(). Если указанная функция разрешена, код вызывает соответствующую функцию из предопределенного набора с помощью функции callAllowedFunction(). Такой подход обеспечивает выполнение только безопасной и целевой функциональности, основанной на белом списке, что снижает риск выполнения произвольного или вредоносного кода.

Благодаря такому подходу совместимый код предотвращает включение функциональности из недоверенного управления и помогает защитить приложение от потенциальных уязвимостей и атак.





## Загрузка кода без проверки целостности

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
const express = require('express');
const app = express();

app.get('/download', (req, res) => {
  const fileName = req.query.filename;

  // Загрузка файла без проверки целостности
  res.download(fileName);
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

В этом коде, не соответствующем требованиям, приложение открывает конечную точку /download, которая принимает параметр запроса имени файла. Код использует функцию res.download() для загрузки файла, указанного пользователем, не выполняя никакой проверки целостности. Такой подход небезопасен, поскольку позволяет пользователям загружать потенциально вредоносные или поддельные файлы, что может привести к уязвимостям в безопасности приложения или скомпрометировать систему пользователя.


Чтобы решить эту проблему, приведем пример кода, который включает проверку целостности перед загрузкой файла:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
const express = require('express');
const app = express();
const fs = require('fs');
const crypto = require('crypto');

app.get('/download', (req, res) => {
  const fileName = req.query.filename;

  // Прочитать содержимое файла
  fs.readFile(fileName, (err, data) => {
    if (err) {
      res.status(404).send('File not found');
      return;
    }

    // Вычислите хэш файла
    const fileHash = crypto.createHash('sha256').update(data).digest('hex');

    // Выполните проверку целостности
    if (isFileIntegrityValid(fileHash)) {
      // Загрузить файл
      res.download(fileName);
    } else {
      res.status(403).send('Integrity check failed');
    }
  });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});

function isFileIntegrityValid(fileHash) {
  // Сравните вычисленный хэш с доверенным хэшем
  const trustedHash = '...'; // Замените на доверенный хэш
  return fileHash === trustedHash;
}
```


В совместимом коде приложение считывает файл, указанный пользователем, с помощью функции fs.readFile() и вычисляет его хэш с помощью безопасной криптографической хэш-функции (в данном примере - sha256). Затем код сравнивает вычисленный хэш с доверенным хэшем, чтобы выполнить проверку целостности с помощью функции isFileIntegrityValid(). Если целостность файла подтверждена, код позволяет загрузить файл с помощью функции res.download(). В противном случае отправляется соответствующий ответ об ошибке.

Реализуя этот подход, совместимый код гарантирует, что файлы будут загружены только после прохождения проверки целостности. Это помогает защитить приложение и его пользователей от загрузки потенциально вредоносных или поддельных файлов, снижая риск возникновения уязвимостей безопасности и нарушения целостности системы.






## Десериализация недоверенных данных

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const deserialize = require('deserialize');

// Среднее программное обеспечение для анализа данных JSON
app.use(bodyParser.json());

app.post('/user', (req, res) => {
  const userData = req.body;

  // Десериализация пользовательских данных без проверки
  const user = deserialize(userData);

  // Обработка пользовательских данных
  // ...

  res.status(200).send('User data processed successfully');
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

В этом коде, не соответствующем требованиям, приложение открывает конечную точку POST /user, которая ожидает JSON-данные, содержащие информацию о пользователе. Код использует библиотеку deserialize для десериализации данных JSON в объект пользователя без выполнения какой-либо проверки или санации. Такой подход небезопасен, поскольку позволяет десериализовать недоверенные данные, что может привести к удаленному выполнению кода, инъекции объектов или другим уязвимостям безопасности.


Чтобы решить эту проблему, приведем пример кода, отвечающего требованиям безопасности, который включает в себя надлежащую проверку и санацию перед десериализацией данных:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const validateUser = require('./validateUser');

// Среднее программное обеспечение для анализа данных JSON
app.use(bodyParser.json());

app.post('/user', (req, res) => {
  const userData = req.body;

  // Проверяем данные пользователя
  const validationResult = validateUser(userData);

  if (validationResult.isValid) {
    // Дезинфекция пользовательских данных
    const sanitizedData = sanitizeUserData(validationResult.data);

    // Десериализуйте пользовательские данные
    const user = deserialize(sanitizedData);

    // Обработка пользовательских данных
    // ...

    res.status(200).send('User data processed successfully');
  } else {
    res.status(400).send('Invalid user data');
  }
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```


В совместимом коде приложение включает этап проверки с помощью функции validateUser() перед десериализацией данных. Функция validateUser() выполняет необходимые проверки и возвращает объект результата проверки, указывающий, являются ли данные действительными или нет. Если данные действительны, код переходит к дезинфекции пользовательских данных с помощью функции sanitizeUserData(), которая гарантирует, что любое потенциально опасное содержимое будет удалено или должным образом обработано. Наконец, дезинфицированные данные десериализуются с помощью функции deserialize(), и приложение может безопасно обрабатывать пользовательские данные.



Благодаря такому подходу совместимый код гарантирует, что недоверенные данные будут должным образом проверены, санированы и десериализованы, что снижает риск возникновения уязвимостей десериализации и защищает приложение от потенциальных эксплойтов безопасности.






## Недостаточное протоколирование

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
const express = require('express');
const app = express();

app.get('/user/:id', (req, res) => {
  const userId = req.params.id;

  // Получение пользователя из базы данных
  const user = db.getUser(userId);

  // Возвращаем данные о пользователе
  res.status(200).json(user);
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

В этом несоответствующем коде приложение имеет конечную точку /user/:id, которая извлекает данные о пользователе на основе предоставленного идентификатора. Однако в коде отсутствует достаточное протоколирование, что затрудняет отслеживание и расследование потенциальных проблем и событий безопасности. Без надлежащего протоколирования становится трудно выявить попытки несанкционированного доступа, подозрительные действия или ошибки, возникающие при получении данных о пользователе.


Чтобы решить эту проблему, приведем пример кода, отвечающего требованиям безопасности, в котором реализована достаточная практика протоколирования:







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
const express = require('express');
const app = express();
const logger = require('winston');

// Настройте регистратор
logger.configure({
  transports: [
    new logger.transports.Console(),
    new logger.transports.File({ filename: 'app.log' })
  ]
});

app.get('/user/:id', (req, res) => {
  const userId = req.params.id;

  // Зарегистрируйте событие извлечения пользователя
  logger.info(`User retrieval requested for id: ${userId}`);

  // Получение пользователя из базы данных
  const user = db.getUser(userId);

  if (user) {
    // Журнал успешного извлечения пользователя
    logger.info(`User retrieved successfully: ${user.name}`);

    // Возвращение данных о пользователе
    res.status(200).json(user);
  } else {
    // Журнал неудачного поиска пользователя
    logger.warn(`User not found for id: ${userId}`);

    // Верните соответствующий ответ на ошибку
    res.status(404).json({ error: 'User not found' });
  }
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```


В совместимом коде приложение использует библиотеку регистрации Winston для регистрации соответствующих событий. Регистратор настроен на два транспорта: консоль для немедленного просмотра во время разработки и файловый транспорт для постоянного протоколирования.

В коде добавлены операторы протоколирования для записи важных событий, таких как запросы на поиск пользователя, успешные и неудачные попытки поиска. Эта информация помогает отслеживать взаимодействие с пользователем и выявлять потенциальные проблемы безопасности или ошибки приложения.

Применяя этот подход, код, отвечающий требованиям, обеспечивает достаточное протоколирование, предоставляя ценную информацию о поведении приложения, событиях, связанных с безопасностью, и потенциальных проблемных областях.



## Неправильная нейтрализация выходных данных в журналах

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
const express = require('express');
const app = express();
const fs = require('fs');

app.get('/user/:id', (req, res) => {
  const userId = req.params.id;

  // Зарегистрируйте событие извлечения пользователя
  const logMessage = `User retrieval requested for id: ${userId}`;
  fs.appendFile('app.log', logMessage, (err) => {
    if (err) {
      console.error('Error writing to log file:', err);
    }
  });

  // Получение пользователя из базы данных
  const user = db.getUser(userId);

  // Возвращаем данные о пользователе
  res.status(200).json(user);
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

В этом несовместимом коде приложение регистрирует событие извлечения пользователя, напрямую добавляя сообщение журнала в файл журнала с помощью fs.appendFile(). Однако сообщение журнала не нейтрализуется должным образом, что может привести к уязвимости инъекции журнала. Злоумышленник может внедрить вредоносное содержимое в сообщение журнала, что приведет к подделке журнала или другим рискам безопасности.


Для решения этой проблемы здесь приведен пример кода, который включает в себя надлежащую нейтрализацию вывода для журналов:







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
const express = require('express');
const app = express();
const fs = require('fs');
const { sanitizeLogMessage } = require('./utils');

app.get('/user/:id', (req, res) => {
  const userId = req.params.id;

  // Зарегистрируйте событие извлечения пользователя
  const logMessage = `User retrieval requested for id: ${sanitizeLogMessage(userId)}`;
  fs.appendFile('app.log', logMessage, (err) => {
    if (err) {
      console.error('Error writing to log file:', err);
    }
  });

  // Получение пользователя из базы данных
  const user = db.getUser(userId);

  // Возвращение данных о пользователе
  res.status(200).json(user);
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```


В совместимом коде появилась отдельная функция sanitizeLogMessage для правильной нейтрализации сообщения журнала. Эта функция может применять необходимые методы экранирования или фильтрации для предотвращения атак инъекции в журнал. Функция sanitizeLogMessage должна быть реализована с помощью соответствующих методов, основанных на формате хранения журнала и требованиях.

Используя надлежащую нейтрализацию вывода, код, соответствующий требованиям, гарантирует, что любой управляемый пользователем ввод, включенный в сообщения журнала, будет надлежащим образом обезврежен или закодирован, что предотвращает уязвимости инъекций в журнал и поддерживает целостность и безопасность записей журнала.





## Упущение информации, имеющей отношение к безопасности

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
const express = require('express');
const app = express();

app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  // Выполните логику входа в систему

  if (loggedIn) {
    res.status(200).send('Login successful');
  } else {
    res.status(401).send('Invalid credentials');
  }
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```


В этом несоответствующем коде приложение обрабатывает функции входа пользователей в систему, но не предоставляет подробных сообщений об ошибках и не регистрирует информацию, имеющую отношение к безопасности. При неудачном входе в систему приложение просто выдает общее сообщение "Неверные учетные данные", что не дает достаточной информации пользователю или администраторам приложения, чтобы понять причину неудачи входа. Отсутствие конкретной информации об ошибке может затруднить устранение неполадок и эффективное решение проблем безопасности.


Чтобы решить эту проблему, приведем пример кода, который включает в себя релевантную для безопасности информацию в сообщениях об ошибках и журналах:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
const express = require('express');
const app = express();

app.post('/login', (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  // Выполните логику входа в систему

  if (loggedIn) {
    res.status(200).send('Login successful');
  } else {
    console.error(`Login failed for username: ${username}`);
    res.status(401).send('Invalid username or password');
  }
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```


В совместимом коде при неудачном входе в систему приложение регистрирует сообщение об ошибке, в котором указывается имя пользователя, с которым не удалось войти в систему. Кроме того, ответное сообщение обновляется, чтобы предоставить более информативное сообщение об ошибке, указывающее, что либо имя пользователя, либо пароль недействительны. Это улучшение помогает выявлять и устранять неполадки при входе в систему, а также предоставлять пользователю более содержательную обратную связь.


Благодаря включению в сообщения об ошибках и журналы информации, имеющей отношение к безопасности, совместимый код повышает уровень безопасности приложения, улучшая видимость и обеспечивая более эффективное реагирование на инциденты и отладку.








## Помещение конфиденциальной информации в файл журнала

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
const express = require('express');
const app = express();

app.get('/user/:id', (req, res) => {
  const userId = req.params.id;

  // Получение информации о пользователе из базы данных
  const user = User.findById(userId);

  // Регистрация информации о пользователе
  console.log(`User information: ${user}`);

  res.status(200).json(user);
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

В этом коде, не соответствующем требованиям, приложение регистрирует конфиденциальную информацию о пользователе с помощью функции console.log. Объект user, содержащий потенциально конфиденциальные данные, напрямую передается в оператор log. Такая практика может привести к тому, что конфиденциальная информация попадет в файлы журнала, сделав их доступными для неавторизованных пользователей или увеличив риск утечки данных.


Чтобы решить эту проблему, приведем пример кода, отвечающего требованиям, который позволяет избежать записи конфиденциальной информации в журнал:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
const express = require('express');
const app = express();

app.get('/user/:id', (req, res) => {
  const userId = req.params.id;

  // Получение информации о пользователе из базы данных
  const user = User.findById(userId);

  // Записывайте в журнал общее сообщение вместо конфиденциальной информации
  console.log(`User requested: ${userId}`);

  res.status(200).json(user);
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```


В совместимом коде приложение регистрирует общее сообщение, указывающее на то, что пользователь был запрошен, не раскрывая напрямую никакой конфиденциальной информации. Избегая регистрации конфиденциальных данных, соответствующий код помогает защитить конфиденциальность пользователей и снижает риск утечки данных через файлы журналов.


Важно помнить, что конфиденциальная информация не должна записываться в журнал открытым текстом или в формате, который можно легко отследить до конкретных лиц или записей данных. Необходимо придерживаться надлежащих методов управления журналами, например, использовать уровни журналов, дезинфицировать журналы и внедрять средства контроля доступа, чтобы ограничить доступ к файлам журналов для авторизованного персонала.






## Подделка запросов со стороны сервера (SSRF)

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
const express = require('express');
const axios = require('axios');

const app = express();

app.get('/fetch', (req, res) => {
  const url = req.query.url;

  // Сделайте запрос на указанный URL
  axios.get(url)
    .then(response => {
      res.status(200).json(response.data);
    })
    .catch(error => {
      res.status(500).json({ error: 'An error occurred while fetching the URL' });
    });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

В этом несоответствующем коде приложение принимает от пользователя параметр url-запроса и напрямую выполняет запрос к этому URL с помощью библиотеки axios. Такой подход представляет значительный риск для безопасности, поскольку злоумышленник может предоставить вредоносный URL, который будет нацелен на внутренние сетевые ресурсы или раскроет конфиденциальную информацию.


Чтобы устранить уязвимость SSRF, приведем пример кода, соответствующего требованиям:







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
const express = require('express');
const axios = require('axios');
const { URL } = require('url');

const app = express();

app.get('/fetch', (req, res) => {
  const url = req.query.url;

  // Проверьте URL, чтобы убедиться, что он не является внутренним ресурсом
  const parsedUrl = new URL(url);
  if (parsedUrl.hostname !== 'example.com') {
    return res.status(400).json({ error: 'Invalid URL' });
  }

  // Сделайте запрос на указанный URL
  axios.get(url)
    .then(response => {
      res.status(200).json(response.data);
    })
    .catch(error => {
      res.status(500).json({ error: 'An error occurred while fetching the URL' });
    });
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});
```

В совместимом коде параметр URL проверяется, чтобы убедиться, что он указывает на разрешенный домен (в данном случае example.com), прежде чем выполнить запрос. Применяя эту проверку, код предотвращает атаки SSRF, разрешая запросы только к доверенным внешним ресурсам.

Важно отметить, что конкретная логика проверки может варьироваться в зависимости от требований приложения и политик безопасности. Приведенный выше пример демонстрирует базовый подход, но для дальнейшего усиления защиты от SSRF следует рассмотреть дополнительные меры безопасности, такие как белые списки IP-адресов, санация ввода и таймаут запроса.
