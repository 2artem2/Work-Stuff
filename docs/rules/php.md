---
layout: default
title: PHP
parent: Rules
---

# PHP
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---





## Раскрытие конфиденциальной информации

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
// Несоответствующий код - раскрытие конфиденциальной информации в журнале ошибок
function processUserInput($input) {
  // Обработка пользовательского ввода
  // ...
  
  // Зафиксировать ошибку с конфиденциальной информацией
  error_log("Error processing user input: $input");
}
```

В этом примере кода, не соответствующем требованиям, функция processUserInput() регистрирует сообщение об ошибке, включающее пользовательский ввод, непосредственно в журнал ошибок. Это может привести к раскрытию конфиденциальной информации для всех, кто имеет доступ к файлу журнала ошибок, включая неавторизованных пользователей.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код


```php
// Соответствующий требованиям код - исключение попадания конфиденциальной информации в журнал ошибок
function processUserInput($input) {
  // Обработка пользовательского ввода
  // ...
  
  // Зафиксировать ошибку без конфиденциальной информации
  error_log("Error processing user input"); // Занесите в журнал общее сообщение об ошибке
}
```


В примере кода, соответствующего требованиям, функция processUserInput() регистрирует общее сообщение об ошибке, не включая в него пользовательский ввод. Избегая включения конфиденциальной информации в журнал ошибок, код снижает риск раскрытия конфиденциальных данных неавторизованным лицам.

Важно отметить, что журнал ошибок должен содержать только информацию, необходимую для отладки, и не должен включать конфиденциальные данные. Кроме того, рекомендуется соответствующим образом настроить параметры журнала ошибок и ограничить доступ к файлам журнала ошибок только для авторизованного персонала.



## Вставка конфиденциальной информации в отправляемые данные

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
<?php
// Этот код отправляет пароль пользователя на удаленный API в качестве части полезной нагрузки в формате JSON
$payload = json_encode(array('username' => 'alice', 'password' => 's3cret'));
$response = file_get_contents('https://example.com/api', null, stream_context_create(array(
    'http' => array(
        'method' => 'POST',
        'header' => "Content-Type: application/json\r\n",
        'content' => $payload,
    ),
)));
?>
```

В приведенном выше коде, не соответствующем требованиям, пароль пользователя включен в полезную нагрузку JSON, которая отправляется удаленному API по HTTPS. Однако, поскольку HTTPS шифрует полезную нагрузку только в пути, но не в состоянии покоя, пароль может быть уязвим для раскрытия, если удаленный API скомпрометирован.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код


```php
<?php
// Этот код отправляет пароль пользователя на удаленный API в качестве параметра URL, используя HTTPS
$username = 'alice';
$password = 's3cret';
$api_url = 'https://example.com/api?username=' . urlencode($username) . '&password=' . urlencode($password);
$response = file_get_contents($api_url, null, stream_context_create(array(
    'http' => array(
        'method' => 'GET',
    ),
)));
?>
```


В приведенном выше коде пароль пользователя не включается в полезную нагрузку, а отправляется в качестве параметра URL с использованием HTTPS. Это гарантирует, что пароль будет зашифрован при передаче и не подвержен раскрытию в случае компрометации удаленного API. Обратите внимание, что использование GET-запросов для отправки конфиденциальной информации не рекомендуется, но этот пример приведен лишь для наглядности. В большинстве случаев более уместным будет POST-запрос.




## Подделка межсайтовых запросов (CSRF)

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
<form action="transfer.php" method="post">
    <input type="hidden" name="amount" value="1000">
    <input type="submit" value="Transfer Funds">
</form>
```

В этом примере, не соответствующем требованиям, форма отправляется PHP-скрипту под названием "transfer.php", который переводит средства. Сумма перевода отправляется в виде скрытого поля формы под названием "amount". Однако этот код не содержит никакой защиты от CSRF, что означает, что злоумышленник может создать форму на другом сайте, которая отправит те же данные в "transfer.php", обманом заставив пользователя перевести средства без его ведома.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код


```php
<?php
session_start();
$_SESSION['token'] = bin2hex(random_bytes(32));
?>

<form action="transfer.php" method="post">
    <input type="hidden" name="amount" value="1000">
    <input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
    <input type="submit" value="Transfer Funds">
</form>
```


В данном примере уникальный токен генерируется и сохраняется в переменной сессии до отображения формы. Затем токен включается в форму в качестве скрытого поля. Когда форма отправляется, токен проверяется в PHP-скрипте, чтобы убедиться, что запрос поступил из легитимного источника. Если токен отсутствует или недействителен, передача не будет разрешена.

Это обеспечивает базовую защиту от CSRF-атак, поскольку злоумышленник не сможет сгенерировать правильный токен, не имея доступа к данным сессии пользователя.



## Использование жестко закодированного пароля

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
// Этот код включает жестко заданный пароль непосредственно в скрипте
$password = "MyHardCodedPassword123";
$connection = mysqli_connect("localhost", "myuser", $password, "mydatabase");
```




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код


```php
// Этот код хранит пароль в отдельном конфигурационном файле с ограниченным доступом
$config = parse_ini_file("/etc/myapp/config.ini");
$connection = mysqli_connect("localhost", "myuser", $config['db_password'], "mydatabase");
```

Жестко закодированные пароли в коде представляют собой угрозу безопасности, так как могут быть легко обнаружены злоумышленниками и использованы для получения несанкционированного доступа. В примере кода, не соответствующем требованиям, пароль непосредственно включен в сценарий, что делает его уязвимым для раскрытия.

В примере кода, соответствующем требованиям, эта проблема решается путем хранения пароля в отдельном конфигурационном файле с ограниченным доступом. Это помогает защитить пароль от легкого обнаружения злоумышленниками и ограничивает его раскрытие авторизованным персоналом, имеющим доступ к файлу конфигурации.




## Нарушенный или небезопасный криптоалгоритм

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
function encryptData($data, $key) {
    $iv = mcrypt_create_iv(16, MCRYPT_DEV_RANDOM);
    $encryptedData = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_CBC, $iv);
    return $encryptedData;
}
```


В этом примере функция encryptData() использует функцию mcrypt_encrypt() с алгоритмом MCRYPT_RIJNDAEL_128 для шифрования. Этот алгоритм считается небезопасным и уязвимым для атак.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код


```php
function encryptData($data, $key) {
    $iv = openssl_random_pseudo_bytes(16);
    $encryptedData = openssl_encrypt($data, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
    return base64_encode($iv . $encryptedData);
}

```
В этом примере функция encryptData() использует функцию openssl_encrypt() с алгоритмом aes-256-cbc для шифрования, который в настоящее время считается безопасным. Кроме того, она использует openssl_random_pseudo_bytes() для генерации случайного вектора инициализации (IV) для каждого шифра, что повышает безопасность шифрования.

Сломанные или рискованные криптографические алгоритмы часто используются в приложениях и системах для защиты конфиденциальных данных. Однако использование таких алгоритмов может привести к появлению уязвимостей, которыми могут воспользоваться злоумышленники. В примере кода, не соответствующем требованиям, для шифрования используется функция mcrypt_encrypt() с алгоритмом MCRYPT_RIJNDAEL_128, который считается небезопасным и уязвимым для атак. В примере совместимого кода вместо этого используется функция openssl_encrypt() с алгоритмом aes-256-cbc, который в настоящее время считается безопасным. Кроме того, функция openssl_random_pseudo_bytes() используется для генерации случайного вектора инициализации для каждого шифра, что еще больше повышает безопасность шифрования.





## Недостаточная энтропия

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
$token = substr(str_shuffle('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'), 0, 8);
```


Недостаточная энтропия может привести к созданию слабых или легко угадываемых ключей, токенов или паролей, что делает их восприимчивыми к атакам методом перебора.

Приведенный выше код генерирует случайный токен из 8 символов путем перетасовки фиксированного набора символов. Однако набор символов слишком мал, и токен легко угадывается и подвержен атакам перебора.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код


```php
$token = bin2hex(random_bytes(16));
```

Приведенный выше код генерирует случайный маркер из 16 байт с помощью функции random_bytes(), которая генерирует криптографически защищенные псевдослучайные байты. Функция bin2hex() преобразует двоичные данные в шестнадцатеричную строку. Полученный токен гораздо прочнее и менее восприимчив к атакам методом перебора.

В целом, чтобы избежать уязвимости недостаточной энтропии, рекомендуется использовать криптографически безопасный генератор случайных чисел, например random_bytes() или openssl_random_pseudo_bytes(), и обеспечить достаточную энтропию выходных данных, например, используя достаточно большой размер ключа или длину пароля.




## Межсайтовый скриптинг (XSS)

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
<?php
$username = $_GET['username'];
echo "Welcome " . $username . "!";
?>
```

Этот код не соответствует требованиям, поскольку принимает ввод непосредственно от пользователя через URL-параметр "username" и отображает его на странице без какой-либо проверки или санации. Злоумышленник может воспользоваться этим, внедрив вредоносный JavaScript-код в параметр "username", который затем выполнится в браузере пользователя, что позволит злоумышленнику выполнить действия от имени пользователя или украсть конфиденциальную информацию.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код


```php
<?php
$username = htmlspecialchars($_GET['username'], ENT_QUOTES, 'UTF-8');
echo "Welcome " . $username . "!";
?>
```


Этот код соответствует требованиям, поскольку использует функцию PHP `htmlspecialchars` для санации пользовательского ввода в параметре "username". Эта функция преобразует специальные символы, такие как `<`, `>` и `&`, в их эквиваленты в HTML, предотвращая их интерпретацию браузером как кода. Флаг `ENT_QUOTES` обеспечивает преобразование одинарных и двойных кавычек в соответствующие сущности, а параметр `'UTF-8`` задает используемую кодировку символов. Благодаря использованию этой функции код эффективно снижает риск XSS-атак.






## SQL-инъекция

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
$username = $_POST['username'];
$password = $_POST['password'];

$sql = "SELECT * FROM users WHERE username='$username' AND password='$password'";
$result = mysqli_query($conn, $sql);
```

Этот код уязвим для атак SQL-инъекций, поскольку использует пользовательский ввод непосредственно в SQL-запросе без какой-либо проверки или санации. Злоумышленник может легко манипулировать вводом и внедрить вредоносный SQL-код.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код


```php
$username = mysqli_real_escape_string($conn, $_POST['username']);
$password = mysqli_real_escape_string($conn, $_POST['password']);

$sql = "SELECT * FROM users WHERE username='$username' AND password='$password'";
$result = mysqli_query($conn, $sql);
```

Этот код использует функцию mysqli_real_escape_string для экранирования специальных символов в пользовательском вводе, что делает его безопасным для использования в SQL-запросе. Тем не менее, стоит отметить, что параметризованные запросы или подготовленные операторы в целом являются лучшим подходом для предотвращения SQL-инъекций в PHP. Вот пример использования параметризованных запросов:

Соответствующий код с параметризованным запросом:


```
$username = $_POST['username'];
$password = $_POST['password'];

$stmt = $conn->prepare("SELECT * FROM users WHERE username=? AND password=?");
$stmt->bind_param("ss", $username, $password);
$stmt->execute();
$result = $stmt->get_result();
```

Этот код использует параметризованный запрос с заполнителями (?) для пользовательского ввода и связывает значения с помощью функции bind_param, что является более безопасным способом предотвращения атак SQL-инъекций.




## Внешнее управление именем или путем файла

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
$filename = $_GET['filename'];
$file = '/path/to/directory/' . $filename;
if (file_exists($file)) {
  // сделайте что-нибудь с файлом
} else {
  // обработать ошибку
}
```


В приведенном выше примере переменная `$filename` берется непосредственно из пользовательского ввода через суперглобальную переменную `$_GET`. Это означает, что злоумышленник может манипулировать значением `$filename`, пытаясь получить доступ к файлам за пределами предполагаемого каталога.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код


```php
$filename = basename($_GET['filename']);
$file = '/path/to/directory/' . $filename;
if (file_exists($file) && is_file($file)) {
  // сделайте что-нибудь с файлом
} else {
  // обработать ошибку
}
```

В совместимом коде функция `basename()` используется для извлечения только части имени файла, вводимой пользователем. Это помогает предотвратить атаки с обходом каталога. Кроме того, функция `is_file()` используется для проверки того, что путь соответствует реальному файлу, а не каталогу или симлинку.





## Формирование сообщения об ошибке, содержащего конфиденциальную информацию

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
<?php
$username = $_POST['username'];
$password = $_POST['password'];
if ($username != 'admin' || $password != 'secretpass') {
  die('Invalid username or password!');
}
?>
```


В таком несоответствующем коде приложение выводит сообщение об ошибке, в котором говорится о том, что имя пользователя или пароль были введены неверно, что может помочь злоумышленнику в атаке методом перебора.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код


```php
<?php
$username = $_POST['username'];
$password = $_POST['password'];
if ($username != 'admin' || $password != 'secretpass') {
  die('Invalid username or password!');
} else {
  // Действительный логин
}
?>
```

В совместимом коде приложение возвращает одно и то же сообщение об ошибке при неправильном имени пользователя или пароле, что усложняет задачу злоумышленника по определению неверного поля.

Кроме того, приложение может быть настроено на регистрацию сообщений об ошибках, содержащих конфиденциальную информацию, и выдачу пользователю более общего сообщения об ошибке. Это позволит системному администратору выявлять и исправлять ошибки, не допуская попадания конфиденциальной информации к потенциальным злоумышленникам.



## незащищенное хранение учетных данных

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
$username = $_POST['username'];
$password = $_POST['password'];
$file = fopen('credentials.txt', 'w');
fwrite($file, "Username: $username, Password: $password");
fclose($file);
```



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код


```php
$username = $_POST['username'];
$password = $_POST['password'];
$hashedPassword = password_hash($password, PASSWORD_DEFAULT);
$dbConnection = mysqli_connect('localhost', 'user', 'password', 'mydatabase');
$query = "INSERT INTO users (username, password) VALUES ('$username', '$hashedPassword')";
mysqli_query($dbConnection, $query);
```

Приведенный выше код, не отвечающий требованиям, записывает введенные имя пользователя и пароль в текстовый файл без какого-либо шифрования или защиты. Это может привести к потенциальной утечке данных, если текстовый файл попадет в чужие руки.

В коде, соответствующем требованиям, пароль сначала хэшируется с помощью функции PHP password_hash(), которая использует надежный алгоритм одностороннего хэширования для безопасного хранения пароля. Затем хэшированный пароль сохраняется в базе данных с помощью подготовленного оператора для предотвращения атак SQL-инъекций.




## Нарушение границ доверия

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
$user_id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = ".$user_id;
$results = mysqli_query($conn, $query);
```

В коде, не соответствующем требованиям, значение `$user_id` берется напрямую из `$_GET`, который является недоверенным источником, а затем используется в SQL-запросе без какой-либо проверки или санации. Это может позволить злоумышленнику изменить SQL-запрос и потенциально извлечь или изменить конфиденциальные данные из базы данных.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код


```php
$user_id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if ($user_id === false) {
    // обработка недопустимого ввода
} else {
    $stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $results = $stmt->get_result();
}
```


В совместимом коде значение `$user_id` фильтруется с помощью `filter_input()` с фильтром `FILTER_VALIDATE_INT`, который гарантирует, что значение является целым числом. Затем используется подготовленный оператор для безопасной передачи значения в SQL-запрос. Это предотвращает атаки SQL-инъекций, правильно отделяя логику запроса от значений данных.





## Недостаточно защищенные учетные данные

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
$password = $_POST['password'];
$hashed_password = sha1($password);
$query = "INSERT INTO users (username, password) VALUES ('{$_POST['username']}', '{$hashed_password}')";
mysqli_query($conn, $query);
```

В этом коде пароль пользователя извлекается из запроса `$_POST` без какой-либо проверки или санации, а затем хэшируется с помощью алгоритма SHA-1, который больше не считается безопасным для хранения паролей. Кроме того, хэшированный пароль вставляется непосредственно в SQL-запрос, что может быть уязвимо для атак SQL-инъекций.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код


```php
$password = $_POST['password'];
if (strlen($password) < 8) {
    // Ошибка обработки: пароль должен состоять не менее чем из 8 символов
}
$salt = bin2hex(random_bytes(16));
$hashed_password = password_hash($password . $salt, PASSWORD_ARGON2ID);
$stmt = $conn->prepare("INSERT INTO users (username, password, salt) VALUES (?, ?, ?)");
$stmt->bind_param("sss", $_POST['username'], $hashed_password, $salt);
$stmt->execute();
```


В этом коде пароль пользователя сначала проверяется, чтобы убедиться, что его длина составляет не менее 8 символов. Затем генерируется случайная 16-байтовая соль с помощью криптографически безопасного генератора случайных чисел. Затем пароль и соль хэшируются с помощью алгоритма Argon2id, который в настоящее время считается одним из самых безопасных алгоритмов хэширования паролей. Наконец, подготовленный оператор вставляет имя пользователя, хэшированный пароль и соль в базу данных, защищая ее от атак SQL-инъекций.





## Ограничение ссылки на внешние сущности XML

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
$xml = simplexml_load_string($xmlstring, 'SimpleXMLElement', LIBXML_NOENT);

// используйте здесь $xml
```

В коде, не соответствующем требованиям, LIBXML_NOENT используется в качестве опции функции simplexml_load_string. Это позволяет парсеру XML обрабатывать ссылки на сущности, что может быть использовано злоумышленником для внедрения вредоносного кода и его выполнения на сервере.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код


```php
$disableEntities = libxml_disable_entity_loader(true);
$xml = simplexml_load_string($xmlstring, 'SimpleXMLElement', LIBXML_NOENT);
libxml_disable_entity_loader($disableEntities);

// используйте здесь $xml
```


В совместимом коде libxml_disable_entity_loader используется для отключения загрузки внешних сущностей в парсер XML. Это не позволяет парсеру разрешать ссылки на внешние сущности, эффективно устраняя уязвимость XXE.





## отображение_ошибок 1

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
// Пример неправильной конфигурации системы безопасности
ini_set('display_errors', 1);
```

В примере несоответствующего кода функция ini_set() используется для включения отображения ошибок пользователю. Это может привести к раскрытию конфиденциальной информации и сообщений об ошибках для злоумышленников.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код


```php
// Пример безопасной конфигурации
// Отключите отображение ошибок для пользователя
ini_set('display_errors', 0);
// Вместо этого записывайте ошибки в защищенный лог-файл
ini_set('error_log', '/var/log/php_errors.log');
```


В примере с совместимым кодом функция ini_set() используется для отключения отображения ошибок пользователю, вместо этого они записываются в защищенный файл журнала. Это позволяет гарантировать, что конфиденциальная информация не попадет к злоумышленникам и что любые ошибки будут должным образом регистрироваться для целей отладки.


## Уязвимые и устаревшие компоненты.

### Библиотека PHPMailer

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
<?php
// Пример уязвимых и устаревших компонентов
// Использование старой версии библиотеки PHPMailer

require_once 'PHPMailer/class.phpmailer.php';

$mail = new PHPMailer();

$mail->IsSMTP();
$mail->SMTPDebug = 1;
$mail->SMTPAuth = true;
$mail->SMTPSecure = 'ssl';

$mail->Host = 'smtp.gmail.com';
$mail->Port = 465;

$mail->Username = 'example@gmail.com';
$mail->Password = 'password';

$mail->SetFrom('from@example.com', 'From Name');
$mail->AddReplyTo('reply@example.com', 'Reply-to Name');

$mail->Subject = 'Test email';
$mail->Body = 'This is a test email';

$mail->AddAddress('recipient@example.com', 'Recipient Name');

if (!$mail->Send()) {
    echo 'Message could not be sent.';
    echo 'Mailer Error: ' . $mail->ErrorInfo;
} else {
    echo 'Message has been sent.';
}
?>
```

Пример несоответствующего кода демонстрирует использование устаревшей версии библиотеки PHPMailer, которая уязвима для эксплойтов безопасности. В частности, она использует уязвимый метод аутентификации, который может быть использован для получения несанкционированного доступа к учетной записи электронной почты, и отправляет письма через незащищенное соединение.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код


```php
<?php
// Пример безопасного и актуального кода
// Использование последней версии библиотеки PHPMailer

require_once 'PHPMailer/src/PHPMailer.php';
require_once 'PHPMailer/src/SMTP.php';

$mail = new PHPMailer\PHPMailer\PHPMailer(true);

$mail->SMTPDebug = SMTP::DEBUG_SERVER;
$mail->isSMTP();
$mail->Host = 'smtp.gmail.com';
$mail->SMTPAuth = true;
$mail->Username = 'example@gmail.com';
$mail->Password = 'password';
$mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
$mail->Port = 587;

$mail->setFrom('from@example.com', 'From Name');
$mail->addAddress('recipient@example.com', 'Recipient Name');

$mail->isHTML(true);
$mail->Subject = 'Test email';
$mail->Body = 'This is a test email';

if (!$mail->send()) {
    echo 'Message could not be sent.';
    echo 'Mailer Error: ' . $mail->ErrorInfo;
```


Пример совместимого кода использует последнюю версию библиотеки PHPMailer, которая имеет улучшенную защиту и соответствует последним передовым практикам безопасности. В частности, она использует безопасный метод аутентификации, отправляет электронные письма через зашифрованное соединение и настроена на отображение отладочной информации на стороне сервера в случае возникновения ошибок.





## Неправильная проверка сертификата с несоответствием хоста

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
$host = $_SERVER['HTTP_HOST'];
$opts = array('ssl' => array('verify_peer' => true, 'CN_match' => $host));
$context = stream_context_create($opts);
$data = file_get_contents('https://example.com', false, $context);
```

В приведенном выше коде, не соответствующем требованиям, переменная `$host` устанавливается на HTTP-хост, предоставленный клиентом. Это означает, что злоумышленник может легко манипулировать заголовком HTTP host и обойти проверку сертификата, установив другой хост. Это может привести к атакам типа "человек посередине".




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код


```php
$host = 'example.com';
$opts = array('ssl' => array('verify_peer' => true, 'CN_match' => $host));
$context = stream_context_create($opts);
$data = file_get_contents('https://'.$host, false, $context);
```


В приведенном выше коде переменная `$host` установлена в доверенное значение, `example.com`. Это гарантирует, что сертификат будет проверен на правильном хосте, и снижает риск атак типа "человек посередине".





## Неправильная аутентификация

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
// Пример 1: слабый пароль
$password = $_POST['password'];
if ($password === 'password123') {
    // Разрешаем доступ
} else {
    // Запретить доступ
}

// Пример 2: Учетные данные с жестким кодом
$username = 'admin';
$password = 'password';
if ($_POST['username'] === $username && $_POST['password'] === $password) {
    // Разрешаем доступ
} else {
    // Запретить доступ
}
```

Примеры несоответствующего кода иллюстрируют две распространенные проблемы неправильной аутентификации. Первый пример демонстрирует использование слабого пароля, который может быть легко угадан злоумышленниками. Второй пример показывает использование жестко закодированных учетных данных, которые могут быть легко обнаружены злоумышленниками.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код


```php
// Пример 1: Сильный пароль
$password = $_POST['password'];
if (password_verify($password, $hashedPassword)) {
    // Разрешаем доступ
} else {
    // Запретить доступ
}

// Пример 2: Хранимые учетные данные
$username = $_POST['username'];
$password = $_POST['password'];

// Проверяем учетные данные пользователя по защищенной базе данных
if (validateCredentials($username, $password)) {
    // Разрешаем доступ
} else {
    // Запретить доступ
}
```


Примеры совместимого кода решают эти проблемы за счет использования надежных алгоритмов хеширования паролей и безопасного хранения учетных данных пользователя в базе данных. В первом примере используется функция `password_verify` для сравнения введенного пользователем пароля с хэшированным паролем, хранящимся в базе данных. Во втором примере учетные данные пользователя проверяются по защищенной базе данных, а не по жестко закодированным учетным данным в коде приложения.





## Фиксация сеанса

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
<?php
session_start();
if (isset($_POST['username']) && isset($_POST['password'])) {
  $username = $_POST['username'];
  $password = $_POST['password'];
  if (authenticate($username, $password)) {
    $_SESSION['authenticated'] = true;
    $_SESSION['username'] = $username;
  }
}
?>
```

В приведенном выше коде, не соответствующем требованиям, идентификатор сессии генерируется при вызове `session_start()`. Однако аутентифицированная сессия не восстанавливается после успешного входа в систему. Это делает сессию пользователя уязвимой для атак с фиксацией сессии.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код


```php
<?php
session_start();
if (isset($_POST['username']) && isset($_POST['password'])) {
  $username = $_POST['username'];
  $password = $_POST['password'];
  if (authenticate($username, $password)) {
    // Регенерация идентификатора сеанса после успешного входа в систему
    session_regenerate_id();
    $_SESSION['authenticated'] = true;
    $_SESSION['username'] = $username;
  }
}
?>
```


В приведенном выше коде функция `session_regenerate_id()` вызывается после успешного входа в систему для регенерации идентификатора сессии. Это гарантирует, что сессия пользователя защищена от атак с фиксацией сессии.





## Включение функциональности из недоверенного управления

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
<?php
$remoteUrl = $_GET['url'];
include($remoteUrl);
?>
```

В этом коде злоумышленник может управлять параметром `url` и указать вредоносный URL, содержащий код, который будет выполнен в контексте приложения. Это может привести к выполнению произвольного кода, раскрытию информации и другим проблемам безопасности.





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код


```php
<?php
$remoteUrl = $_GET['url'];
if (filter_var($remoteUrl, FILTER_VALIDATE_URL)) {
  include($remoteUrl);
} else {
  // ошибка обработки
}
?>
```


В совместимом коде добавлена проверка ввода, чтобы убедиться, что параметр `url` является действительным URL-адресом, прежде чем включить удаленный файл. Это снижает риск включения вредоносного файла и защищает от возможного выполнения кода и других проблем безопасности.



## Загрузка кода без проверки целостности

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
$url = 'https://example.com/package.tar.gz';
$pkg = file_get_contents($url);
file_put_contents('/tmp/package.tar.gz', $pkg);
system('tar -xvf /tmp/package.tar.gz');
```

В этом примере код загружает пакет tarball из удаленного места и извлекает его содержимое. Однако код не проверяет целостность загруженного пакета перед использованием, что делает его восприимчивым к взлому злоумышленниками.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код


```php
$url = 'https://example.com/package.tar.gz';
$hash = file_get_contents($url . '.sha256');
$pkg = file_get_contents($url);

if (hash('sha256', $pkg) === trim($hash)) {
    file_put_contents('/tmp/package.tar.gz', $pkg);
    system('tar -xvf /tmp/package.tar.gz');
} else {
    throw new Exception('Package hash does not match expected value');
}
```


В совместимом коде целостность загруженного пакета проверяется с помощью хэша SHA-256. Хэш загружается из доверенного источника (например, из хранилища пакетов), и загруженный пакет сравнивается с ожидаемым хэшем. Если хэши совпадают, пакет сохраняется и извлекается; в противном случае возникает исключение.




## Десериализация недоверенных данных

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
// Несоответствующий код для десериализации недоверенных данных

// Функция unserialize() используется для десериализации входных данных из строки
$userData = unserialize($_COOKIE['user']);

// Используем данные из $userData
$name = $userData['name'];
$id = $userData['id'];
```

В этом несовместимом коде функция `unserialize()` используется для десериализации введенных пользователем данных из массива `$_COOKIE` напрямую, без какой-либо проверки или санации. Это может быть опасно, поскольку злоумышленник может манипулировать входными данными для выполнения вредоносного кода во время процесса десериализации.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код


```php
// Соответствующий код для десериализации недоверенных данных

// Десериализуйте входные данные после их валидации и санации
$userData = json_decode(filter_input(INPUT_COOKIE, 'user', FILTER_SANITIZE_STRING));

// Используем данные из $userData
if (isset($userData->name)) {
    $name = $userData->name;
}
if (isset($userData->id)) {
    $id = $userData->id;
}
```


В этом совместимом коде входные данные из массива `$_COOKIE` сначала проверяются и обеззараживаются с помощью функции `filter_input()` с фильтром `FILTER_SANITIZE_STRING`. Затем входные данные десериализуются с помощью функции `json_decode()`, которая является более безопасной, чем `unserialize()`, поскольку десериализует только данные в формате JSON.

Наконец, данные из `$userData` используются только после проверки наличия ожидаемых свойств с помощью функции `isset()`, что снижает риск получения доступа к неожиданным свойствам или выполнения вредоносного кода.




## Недостаточное протоколирование

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
function transferMoney($amount, $recipient) {
  // немного кода для перевода денег
  // ...
  
  // регистрируем транзакцию
  file_put_contents('transaction.log', "Transfered $amount to $recipient", FILE_APPEND);
}
```

В приведенном выше коде функция transferMoney записывает информацию о транзакциях в файл, но этого недостаточно. В нем нет временных меток, уровней серьезности или любой другой полезной информации, которая могла бы помочь обнаружить или расследовать инциденты безопасности.





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код


```php
function transferMoney($amount, $recipient) {
  // немного кода для перевода денег
  // ...
  
  // регистрируем транзакцию с полезной информацией
  $log = fopen('transaction.log', 'a');
  if ($log) {
    $datetime = date('Y-m-d H:i:s');
    $severity = 'INFO';
    $message = "Transfered $amount to $recipient";
    $entry = "$datetime [$severity]: $message\n";
    fwrite($log, $entry);
    fclose($log);
  } else {
    error_log('Unable to open transaction log file');
  }
}
```


В совместимом коде функция `transferMoney` регистрирует информацию о транзакциях в файл с полезной информацией, такой как временная метка, уровень серьезности и форматированное сообщение. Кроме того, функция обрабатывает ошибки, которые могут возникнуть при регистрации, например невозможность открыть файл журнала, путем записи сообщения об ошибке в системный журнал. Это позволяет быстро и эффективно обнаруживать и расследовать инциденты безопасности.



## Неправильная нейтрализация выхода для бревен

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
$username = $_POST['username'];
$password = $_POST['password'];

// записать имя пользователя и пароль в файл
file_put_contents('logs.txt', 'Username: '.$username.' Password: '.$password);
```

В примере кода, не отвечающего требованиям, переменные `$_POST` не подвергаются санитарной обработке перед записью в файл. Это может позволить злоумышленнику внедрить вредоносный ввод и записать его в файл, что может привести к компрометации системы.





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код


```php
$username = $_POST['username'];
$password = $_POST['password'];

// Дезинфекция входных данных с помощью filter_var
$sanitized_username = filter_var($username, FILTER_SANITIZE_STRING, FILTER_FLAG_STRIP_LOW | FILTER_FLAG_STRIP_HIGH);
$sanitized_password = filter_var($password, FILTER_SANITIZE_STRING, FILTER_FLAG_STRIP_LOW | FILTER_FLAG_STRIP_HIGH);

// записываем продезинфицированные имя пользователя и пароль в файл
file_put_contents('logs.txt', 'Username: '.$sanitized_username.' Password: '.$sanitized_password);
```


В примере с совместимым кодом функция `filter_var` используется для дезинфекции входных данных перед записью в файл. Флаг `FILTER_SANITIZE_STRING` удаляет любой символ, который не является буквой, цифрой или пробелом. Флаги `FILTER_FLAG_STRIP_LOW` и `FILTER_FLAG_STRIP_HIGH` удаляют любой символ со значением ASCII ниже 32 или выше 126, соответственно. Это гарантирует, что в файл будут записываться только безопасные и допустимые символы.





## Упущение информации, имеющей отношение к безопасности

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
$username = $_POST['username'];
$password = $_POST['password'];

$sql = "SELECT * FROM users WHERE username = '" . $username . "' AND password = '" . $password . "'";
$result = mysqli_query($conn, $sql);

if (mysqli_num_rows($result) > 0) {
    // пользователь аутентифицирован
    // выполните какую-то конфиденциальную операцию
} else {
    // пользователь не аутентифицирован
    echo "Invalid credentials";
}
```




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код


```php
$username = $_POST['username'];
$password = $_POST['password'];

$sql = "SELECT * FROM users WHERE username = ? AND password = ?";
$stmt = mysqli_prepare($conn, $sql);
mysqli_stmt_bind_param($stmt, "ss", $username, $password);
mysqli_stmt_execute($stmt);
$result = mysqli_stmt_get_result($stmt);

if (mysqli_num_rows($result) > 0) {
    // пользователь аутентифицирован
    // выполните какую-то конфиденциальную операцию
} else {
    // пользователь не аутентифицирован
    echo "Invalid credentials";
}
```


Упущение информации, имеющей отношение к безопасности, - это уязвимость, которая возникает, когда важная информация, связанная с безопасностью, например сообщения об ошибках, не предоставляется пользователю или не регистрируется для последующего анализа. В примере с несоответствующим кодом злоумышленник может использовать сообщение об ошибке "Invalid credentials", чтобы определить, существует ли данное имя пользователя в системе. Эта информация может быть использована в дальнейших атаках для попытки угадать правильный пароль. Соответствующий пример кода использует подготовленные операторы для предотвращения SQL-инъекций и не предоставляет никакой информации в сообщении об ошибке, которая может быть использована злоумышленником для определения того, существует ли имя пользователя в системе или нет.






## Помещение конфиденциальной информации в файл журнала

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
// конфиденциальные данные регистрируются без надлежащего редактирования
$username = $_POST['username'];
$password = $_POST['password'];

error_log("Login attempt with username: ".$username." and password: ".$password);
```

Несоответствующий требованиям код показывает пример, в котором конфиденциальные данные (например, имя пользователя и пароль) напрямую записываются в файл журнала ошибок. Это может быть опасно, так как может привести к раскрытию этой конфиденциальной информации неавторизованным лицам, имеющим доступ к файлу журнала.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код


```php
// конфиденциальные данные редактируются перед записью в журнал
$username = $_POST['username'];
$password = $_POST['password'];

error_log("Login attempt with username: ".redact($username)." and password: ".redact($password));

function redact($string) {
  // замените конфиденциальные данные на звездочки
  return preg_replace('/./', '*', $string);
}
```


В совместимом коде показан пример того, как правильно отредактировать конфиденциальные данные перед их записью в журнал. В этом примере функция redact заменяет каждый символ в конфиденциальной строке на звездочку, эффективно скрывая конфиденциальные данные. Затем отредактированные строки используются в сообщении журнала ошибок, которое не раскрывает конфиденциальные данные.




## Подделка запросов со стороны сервера (SSRF)

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
$url = $_GET['url'];
$file = file_get_contents($url);
echo $file;
```

В этом несовместимом коде злоумышленник может передать вредоносный URL через параметр "url" в GET-запросе, и сервер выполнит запрос к этому URL с помощью функции file_get_contents(). Это позволяет злоумышленнику выполнить несанкционированные действия от имени сервера.





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код


```php
$url = $_GET['url'];
if (filter_var($url, FILTER_VALIDATE_URL) === FALSE) {
    echo "Invalid URL";
} else {
    $file = file_get_contents($url);
    echo $file;
}
```


В этом совместимом коде входные данные из параметра "url" проверяются с помощью фильтра FILTER_VALIDATE_URL, который проверяет, является ли URL действительным. Если URL недействителен, сценарий вернет сообщение об ошибке. Если URL действителен, сервер получит содержимое URL с помощью функции file_get_contents(). Это предотвращает выполнение сервером запросов к вредоносным URL.


Важно отметить, что помимо проверки ввода, другие меры, такие как использование белого списка разрешенных URL и ограничение доступа к сети, также могут помочь предотвратить атаки SSRF.

