---
layout: default
title: Laravel
parent: Rules
---

# Laravel
{: .no_toc }


## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---




### Межсайтовый скриптинг (XSS)

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
// Несоответствующий код
public function store(Request $request)
{
    $name = $request->input('name');
    $message = $request->input('message');
    
    DB::table('comments')->insert([
        'name' => $name,
        'message' => $message,
    ]);
    
    return redirect()->back();
}
```

В этом несоответствующем коде метод store получает пользовательский ввод через объект $request и напрямую вставляет его в базу данных без какой-либо проверки или санитарной обработки. Это делает приложение уязвимым к атакам межсайтового скриптинга (XSS), поскольку злоумышленник может отправить вредоносный JavaScript-код в качестве входного сообщения, которое будет отображено как есть при возврате пользователю.





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
// Соответствующий код
public function store(Request $request)
{
    $name = $request->input('name');
    $message = $request->input('message');
    
    $sanitizedMessage = htmlspecialchars($message, ENT_QUOTES, 'UTF-8');
    
    DB::table('comments')->insert([
        'name' => $name,
        'message' => $sanitizedMessage,
    ]);
    
    return redirect()->back();
}
```


В соответствующем коде функция htmlspecialchars используется для санитарной обработки пользовательского ввода перед вставкой его в базу данных. Эта функция экранирует специальные символы, которые имеют особое значение в HTML, предотвращая их интерпретацию как HTML-тегов или сущностей при отображении в браузере. Этот процесс дезинфекции помогает уменьшить уязвимости XSS, гарантируя, что вводимые пользователем данные будут рассматриваться как обычный текст, а не как исполняемый код.

Важно отметить, что хотя функция htmlspecialchars обеспечивает базовую защиту от XSS-атак, она зависит от контекста. В зависимости от конкретного контекста вывода (например, атрибуты HTML, JavaScript, CSS) может потребоваться дополнительная санация или кодирование. Для более полной защиты от XSS-уязвимостей следует использовать специализированные библиотеки или функции, адаптированные к конкретному контексту вывода.

В дополнение к санации ввода, другие меры безопасности, которые вы можете реализовать в Laravel для снижения уязвимостей XSS, включают:

* Использование встроенной в Laravel защиты CSRF для предотвращения атак подделки межсайтовых запросов.
* Применение кодировки вывода с помощью шаблонизатора Laravel Blade или вспомогательных функций, таких как {{ }}, для автоматического экранирования переменных.
* Реализация политик безопасности контента (CSP) для контроля типов контента, разрешенных для загрузки и выполнения на ваших веб-страницах.

Правильная санация пользовательского ввода и применение мер безопасности во всем приложении Laravel позволят вам эффективно устранить XSS-уязвимости и повысить общую безопасность вашего веб-приложения.









### SQL-инъекция

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
$userInput = $_GET['username'];
$query = "SELECT * FROM users WHERE username = '".$userInput."'";
$results = DB::select($query);
```

В этом несовместимом коде пользовательский ввод напрямую конкатенируется в строку SQL-запроса, что создает уязвимость, известную как SQL-инъекция. Злоумышленник может манипулировать вводом, чтобы внедрить вредоносные SQL-запросы, потенциально получив несанкционированный доступ к базе данных или манипулируя ее содержимым.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
$userInput = $_GET['username'];
$results = DB::select("SELECT * FROM users WHERE username = ?", [$userInput]);
```


В соответствующем коде конструктор запросов Laravel используется вместе с подготовленными операторами для защиты от SQL-инъекций. Пользовательский ввод привязывается к заполнителю (?) в запросе, а Laravel обрабатывает правильное экранирование и дезинфекцию ввода.

Благодаря использованию подготовленных операторов совместимый код гарантирует, что пользовательский ввод будет рассматриваться как данные, а не как исполняемый SQL-код, тем самым предотвращая атаки SQL-инъекций.








### Нарушенный контроль доступа

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
public function deletePost(Request $request, $postId)
{
    $post = Post::find($postId);
    
    // Проверьте, является ли текущий аутентифицированный пользователь владельцем сообщения
    if ($post->user_id == Auth::user()->id) {
        $post->delete();
        return redirect('/dashboard')->with('success', 'Post deleted successfully.');
    } else {
        return redirect('/dashboard')->with('error', 'You do not have permission to delete this post.');
    }
}
```

В этом несоответствующем коде метод deletePost предполагает, что текущий аутентифицированный пользователь имеет право удалять любые сообщения, основываясь только на своем идентификаторе пользователя. Однако он не выполняет надлежащих проверок контроля доступа, чтобы убедиться, что пользователь является фактическим владельцем сообщения. Это может привести к нарушению контроля доступа, позволяя неавторизованным пользователям удалять сообщения.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
public function deletePost(Request $request, $postId)
{
    $post = Post::find($postId);
    
    // Проверьте, является ли текущий аутентифицированный пользователь владельцем сообщения
    if ($post->user_id == Auth::user()->id) {
        $post->delete();
        return redirect('/dashboard')->with('success', 'Post deleted successfully.');
    } else {
        abort(403, 'Unauthorized');
    }
}
```

В соответствующем коде метод deletePost выполняет ту же проверку, чтобы убедиться, что аутентифицированный пользователь является владельцем сообщения. Однако вместо перенаправления с сообщением об ошибке он выбрасывает исключение 403 Forbidden с помощью функции abort, если пользователь не авторизован. Это гарантирует, что неавторизованные пользователи не смогут узнать о существовании поста, к которому у них нет доступа.








### Криптографические сбои

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
public function encryptData($data, $key)
{
    return encrypt($data, $key);
}

public function decryptData($encryptedData, $key)
{
    return decrypt($encryptedData, $key);
}
```

В этом несоответствующем коде функции encryptData и decryptData используют стандартные функции шифрования Laravel encrypt и decrypt для выполнения криптографических операций. Однако в этом коде не учитываются важные аспекты криптографической безопасности, такие как управление ключами, выбор алгоритмов и безопасная обработка конфиденциальных данных. Это может привести к сбоям в работе криптографии и уязвимостям в приложении.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
use Illuminate\Support\Facades\Crypt;

public function encryptData($data, $key)
{
    return Crypt::encryptString($data);
}

public function decryptData($encryptedData, $key)
{
    try {
        return Crypt::decryptString($encryptedData);
    } catch (DecryptException $e) {
        // Обработка ошибки расшифровки
    }
}
```


В соответствующем коде мы используем фасад Laravel Crypt для выполнения операций шифрования и дешифрования. Методы encryptString и decryptString, предоставляемые фасадом Crypt, обеспечивают более безопасный подход к криптографическим операциям. Кроме того, обработка ошибок реализована с помощью блока try-catch для правильной обработки ошибок расшифровки, например, при предоставлении неверного ключа.






### Небезопасное конструирование

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
public function getUserProfile($userId)
{
    $user = User::find($userId);

    if ($user) {
        return [
            'id' => $user->id,
            'name' => $user->name,
            'email' => $user->email,
            'role' => $user->role,
        ];
    }

    return null;
}
```

В этом коде, не соответствующем требованиям, функция getUserProfile извлекает информацию о профиле пользователя на основе предоставленного $userId. Однако в ней отсутствуют надлежащие проверки контроля доступа и авторизации. Любой пользователь потенциально может получить доступ к информации профиля любого другого пользователя, минуя необходимые меры безопасности.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
public function getUserProfile($userId, $requestingUserId)
{
    $requestingUser = User::find($requestingUserId);

    if ($requestingUser && $requestingUser->isAdmin()) {
        $user = User::find($userId);

        if ($user) {
            return [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'role' => $user->role,
            ];
        }
    }

    return null;
}
```

В коде, соответствующем требованиям, мы ввели дополнительный параметр $requestingUserId для идентификации пользователя, делающего запрос. Сначала мы проверяем, существует ли запрашивающий пользователь и обладает ли он необходимыми привилегиями, например правами администратора, для доступа к информации о профиле. Только если эти условия выполнены, информация о профиле возвращается. В противном случае возвращается null, указывающий на отсутствие авторизации.







### Неправильная конфигурация системы безопасности

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
// config/database.php

return [
    'default' => 'mysql',
    'connections' => [
        'mysql' => [
            'driver' => 'mysql',
            'host' => '127.0.0.1',
            'port' => '3306',
            'database' => 'mydatabase',
            'username' => 'root',
            'password' => '',
            'unix_socket' => '',
            'charset' => 'utf8mb4',
            'collation' => 'utf8mb4_unicode_ci',
            'prefix' => '',
            'strict' => false,
            'engine' => null,
        ],
    ],
];
```

В этом несоответствующем коде файл конфигурации базы данных config/database.php содержит конфиденциальную информацию, такую как учетные данные базы данных. Поле пароля пустое, что означает, что приложение использует пароль по умолчанию или слабый пароль, что делает его уязвимым для несанкционированного доступа. Кроме того, отключен строгий режим, что может привести к небезопасным SQL-запросам.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
// config/database.php

return [
    'default' => env('DB_CONNECTION', 'mysql'),
    'connections' => [
        'mysql' => [
            'driver' => 'mysql',
            'host' => env('DB_HOST', '127.0.0.1'),
            'port' => env('DB_PORT', '3306'),
            'database' => env('DB_DATABASE', 'mydatabase'),
            'username' => env('DB_USERNAME', 'root'),
            'password' => env('DB_PASSWORD', ''),
            'unix_socket' => env('DB_SOCKET', ''),
            'charset' => 'utf8mb4',
            'collation' => 'utf8mb4_unicode_ci',
            'prefix' => '',
            'strict' => true,
            'engine' => null,
        ],
    ],
];
```


В соответствующем коде конфиденциальная информация, такая как учетные данные базы данных, не записывается непосредственно в конфигурационный файл. Вместо этого для получения значений используются переменные окружения. Это позволяет повысить безопасность, поскольку конфиденциальная информация хранится отдельно от кодовой базы и настраивается в зависимости от среды развертывания.



Используя переменные окружения, вы можете легко управлять различными конфигурациями для сред разработки, тестирования и производства, не раскрывая конфиденциальную информацию в кодовой базе или системе контроля версий.






### Уязвимые и устаревшие компоненты

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
composer require laravel/framework:5.7.0
```

В этом несоответствующем коде явно указана версия фреймворка Laravel 5.7.0. Это может привести к использованию уязвимой и устаревшей версии фреймворка, так как более новые версии могут содержать исправления безопасности и ошибок.







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
composer require laravel/framework:^8.0
```


В соответствующем коде версия фреймворка Laravel указывается с помощью ограничения версии ^8.0. Это позволяет Composer, менеджеру зависимостей PHP, установить последнюю совместимую версию фреймворка Laravel в рамках основной версии 8.x. Это гарантирует, что вы получите последние обновления и улучшения безопасности.






### Сбои в идентификации и аутентификации

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
public function login(Request $request)
{
    $credentials = $request->only('email', 'password');
    
    if (Auth::attempt($credentials)) {
        // Пользователь успешно прошел аутентификацию
        return redirect()->intended('/dashboard');
    } else {
        // Аутентификация не удалась
        return redirect()->back()->withErrors(['Invalid credentials']);
    }
}
```

В этом несоответствующем коде процесс аутентификации опирается исключительно на метод Auth::attempt(), который пытается аутентифицировать пользователя на основе предоставленных им электронной почты и пароля. Однако этот код не обрабатывает должным образом некоторые сбои аутентификации, такие как блокировка учетной записи или защита от перебора.







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
public function login(Request $request)
{
    $credentials = $request->only('email', 'password');
    
    if (Auth::attempt($credentials)) {
        // Пользователь успешно прошел аутентификацию
        return redirect()->intended('/dashboard');
    } else {
        // Аутентификация не удалась
        if (Auth::exists(['email' => $request->input('email')])) {
            // Введен неверный пароль
            return redirect()->back()->withErrors(['Invalid password']);
        } else {
            // Указан неверный адрес электронной почты
            return redirect()->back()->withErrors(['Invalid email']);
        }
    }
}
```


В соответствующем коде мы усовершенствовали процесс аутентификации, рассмотрев различные типы сбоев аутентификации. Если указанная электронная почта существует в базе данных системы, но пароль неверен, мы выводим соответствующее сообщение об ошибке, указывающее на недействительный пароль. Если указанный e-mail не существует, мы выдаем сообщение об ошибке, указывая на недействительный e-mail.






### Сбои в работе программного обеспечения и целостности данных

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
public function updateProfile(Request $request)
{
    $user = Auth::user();

    $user->name = $request->input('name');
    $user->email = $request->input('email');
    $user->save();

    return redirect('/profile');
}
```

В этом коде, не соответствующем требованиям, информация о профиле пользователя обновляется непосредственно на основе пользовательского ввода, полученного из запроса. Хотя этот код успешно обновляет имя и электронную почту пользователя, в нем отсутствует надлежащая проверка и санитарная обработка вводимых данных, что может привести к сбоям в работе программного обеспечения и целостности данных.







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
public function updateProfile(Request $request)
{
    $user = Auth::user();

    $validatedData = $request->validate([
        'name' => 'required|string|max:255',
        'email' => 'required|email|unique:users,email,' . $user->id,
    ]);

    $user->name = $validatedData['name'];
    $user->email = $validatedData['email'];
    $user->save();

    return redirect('/profile');
}
```


В соответствующем коде мы добавили правила валидации, чтобы обеспечить целостность программного обеспечения и данных. Метод validate() используется для проверки полей ввода на соответствие определенным правилам. В данном примере поле "Имя" является обязательным и должно быть строкой длиной не более 255 символов. Поле электронной почты также является обязательным и должно иметь правильный формат. Кроме того, поле email проверяется на уникальность, чтобы убедиться, что ни один пользователь в базе данных не имеет такого же email.





### Сбои в работе журналов безопасности и мониторинга

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
public function deleteUser(Request $request)
{
    $userId = $request->input('user_id');

    $user = User::find($userId);

    if ($user) {
        $user->delete();
    }

    return redirect('/users');
}
```

В этом несоответствующем коде, когда пользователь удаляется, нет механизма регистрации или мониторинга для отслеживания этой активности. Код просто удаляет пользователя, если он найден, и перенаправляет обратно к списку пользователей. Без надлежащего протоколирования и мониторинга становится сложно выявить и расследовать любые несанкционированные или подозрительные случаи удаления пользователей.







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
public function deleteUser(Request $request)
{
    $userId = $request->input('user_id');

    $user = User::find($userId);

    if ($user) {
        $user->delete();

        // Зарегистрируйте действия по удалению пользователя
        Log::info('User deleted', ['user_id' => $userId]);
    }

    return redirect('/users');
}
```


В соответствующем коде мы добавили механизм ведения журнала для отслеживания действий по удалению пользователя. После успешного удаления пользователя мы используем фасад Laravel's Log для записи в журнал на информационном уровне. Сообщение в журнале содержит такие важные детали, как идентификатор пользователя, который был удален. Включив ведение журнала в код, мы можем вести учет важных событий, связанных с безопасностью, и создавать аудиторский след для последующего анализа и мониторинга.





### Подделка запросов на стороне сервера

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
public function fetchExternalData(Request $request)
{
    $url = $request->input('url');

    $data = file_get_contents($url);

    return response()->json(['data' => $data]);
}
```

В этом несовместимом коде метод fetchExternalData принимает от пользователя URL-адрес и напрямую использует функцию file_get_contents для получения данных с этого URL-адреса. Это может привести к уязвимости Server-Side Request Forgery, когда злоумышленник может предоставить вредоносный URL, который заставит приложение выполнить непредусмотренные действия или получить доступ к внутренним ресурсам.







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
public function fetchExternalData(Request $request)
{
    $url = $request->input('url');

    // Проверяем и санируем URL для предотвращения SSRF
    $validatedUrl = filter_var($url, FILTER_VALIDATE_URL);
    
    if (!$validatedUrl) {
        return response()->json(['error' => 'Invalid URL'], 400);
    }

    // При необходимости ограничьте разрешенные домены
    $allowedDomains = ['example.com', 'trusteddomain.com'];
    $parsedUrl = parse_url($validatedUrl);
    
    if (!in_array($parsedUrl['host'], $allowedDomains)) {
        return response()->json(['error' => 'Access to the specified domain is not allowed'], 403);
    }

    // Получение данных
    $data = file_get_contents($validatedUrl);

    return response()->json(['data' => $data]);
}
```


В соответствующем коде предпринято несколько мер по снижению уязвимости Server-Side Request Forgery:

1. Валидация и санация URL: Вводимый URL проверяется и санируется с помощью функции filter_var с фильтром FILTER_VALIDATE_URL. Это гарантирует, что URL, предоставленный пользователем, является действительным.

1. Ограничение разрешенных доменов: При необходимости можно вести белый список доверенных доменов. Разбираемый хост URL проверяется по этому списку, чтобы гарантировать доступ только к доверенным доменам. Это помогает предотвратить доступ к потенциально вредоносным или внутренним ресурсам.

1. Правильная обработка ошибок: В случае недействительного URL или неавторизованного домена возвращаются соответствующие ответы об ошибках. Это гарантирует, что потенциальные попытки SSRF будут правильно обработаны и доведены до сведения пользователя или клиента.
















