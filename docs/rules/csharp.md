---
layout: default
title: Csharp
parent: Rules
---

# Csharp
{: .no_toc }


## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---







## Раскрытие конфиденциальной информации

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
using System;

class Program
{
    static void Main()
    {
        try
        {
            // Моделирование ошибки
            throw new Exception("An error occurred: Sensitive information");
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
        }
    }
}
```

В этом несоответствующем коде оператор throw намеренно генерирует исключение с сообщением об ошибке, которое содержит конфиденциальную информацию, например строку подключения к базе данных, пароль или любые другие конфиденциальные данные. Сообщение об ошибке выводится на консоль, что может привести к раскрытию конфиденциальной информации для неавторизованных пользователей или злоумышленников.


Чтобы решить эту проблему и предотвратить передачу конфиденциальной информации через сообщения об ошибках, приведем пример соответствующего кода:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
using System;

класс Program
{
    static void Main()
    {
        try
        {
            // Имитация ошибки
            throw new Exception("Произошла ошибка");
        }
        catch (Exception ex)
        {
            Console.WriteLine("Произошла непредвиденная ошибка");
            // Зафиксируйте исключение в журнале для целей отладки или мониторинга
            LogException(ex);
        }
    }

    static void LogException(Exception ex)
    {
        // Зафиксируйте исключение в безопасном файле журнала или в службе регистрации.
        // Включите необходимую информацию для отладки, но избегайте конфиденциальных данных
        Console.WriteLine("Произошла ошибка: " + ex.ToString());
    }
}
```


В соответствующем коде в сообщении об ошибке намеренно не указывается конфиденциальная информация, а вместо нее выдается общее сообщение об ошибке. Конфиденциальная информация регистрируется на стороне сервера для целей отладки или мониторинга, но не передается пользователю или клиенту.


Благодаря тому, что сообщения об ошибках не содержат конфиденциальной информации, соответствующий код снижает риск раскрытия конфиденциальных данных потенциальным злоумышленникам или неавторизованным пользователям.




Semgrep:


```
rules:
  - id: sensitive-information-exposure
    patterns:
      - pattern: 'catch \(Exception ex\)\n\s+Console\.WriteLine\(ex\.Message\);'
    message: "Sensitive information exposure in exception handling"
```

CodeQL:



```
import csharp

from TryCatchStatement tryCatch
where exists(CatchClause catchClause |
  catchClause.getParameter().getType().toString() = "System.Exception" and
  exists(MethodInvocation println |
    println.getTarget().toString() = "System.Console.WriteLine" and
    println.getArgument(0).toString().indexOf("ex.Message") >= 0
  )
)
select tryCatch
```



## Вставка конфиденциальной информации в отправленные данные

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
using System;
using System.Net;
using System.Net.Mail;

class Program
{
    static void Main()
    {
        string username = "user";
        string password = "password";
        string recipient = "example@example.com";
        string sensitiveData = "Sensitive information";

        using (var client = new SmtpClient("smtp.example.com", 587))
        {
            client.EnableSsl = true;
            client.Credentials = new NetworkCredential(username, password);

            var message = new MailMessage("sender@example.com", recipient, "Subject", "Body: " + sensitiveData);

            client.Send(message);
        }
    }
}
```

В этом несоответствующем коде конфиденциальная информация (хранящаяся в переменной sensitiveData) конкатенируется с телом письма без какого-либо шифрования или обфускации. Это означает, что конфиденциальные данные напрямую включаются в отправляемые данные без какой-либо защиты, что может привести к потенциальному раскрытию или несанкционированному доступу к информации.


Чтобы решить эту проблему и обеспечить защиту конфиденциальной информации в отправляемых данных, вот пример соответствующего кода:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
using System;
using System.Net;
using System.Net.Mail;

class Program
{
    static void Main()
    {
        string username = "user";
        string password = "password";
        string recipient = "example@example.com";
        string sensitiveData = "Sensitive information";

        using (var client = new SmtpClient("smtp.example.com", 587))
        {
            client.EnableSsl = true;
            client.Credentials = new NetworkCredential(username, password);

            var message = new MailMessage("sender@example.com", recipient, "Subject", "Body");

            // Прикрепите конфиденциальные данные в виде защищенного вложения
            var attachment = new Attachment(sensitiveData);
            message.Attachments.Add(attachment);

            client.Send(message);
        }
    }
}
```


В соответствующем коде вместо непосредственной вставки конфиденциальной информации в тело письма она прикрепляется в виде защищенного вложения. Это помогает защитить конфиденциальные данные во время передачи, гарантируя, что они не будут раскрыты в отправленных данных.

Благодаря правильной обработке конфиденциальной информации и отказу от прямой вставки в отправляемые данные, соответствующий код повышает безопасность и конфиденциальность конфиденциальных данных, снижая риск несанкционированного доступа или раскрытия.




Semgrep:


```
rules:
  - id: sensitive-information-exposure
    patterns:
      - pattern: 'new MailMessage\(.+\, ".+"\, ".+"\, "Body: .+"\)'
    message: "Sensitive information exposure in email communication"
```

CodeQL:



```
import csharp

from ObjectCreation messageCreation
where messageCreation.getType().toString() = "System.Net.Mail.MailMessage" and
  messageCreation.getArgument(3).toString().indexOf("Body:") >= 0
select messageCreation
```




## Подделка межсайтовых запросов (CSRF)

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
using System;
using System.Web.UI;

public partial class MyPage : Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        // Несоответствующий требованиям код: Защита от CSRF не реализована
        if (Request.QueryString["action"] == "delete")
        {
            string id = Request.QueryString["id"];
            // Удаление записи с заданным идентификатором
            // ...
        }
    }
}
```

В этом несоответствующем коде страница выполняет действие удаления на основе параметра запроса action и идентификатора, указанного в параметре запроса id. Однако здесь не реализована защита от CSRF, а это значит, что злоумышленник может создать вредоносную ссылку или форму на другом сайте, которая выполнит действие удаления от имени пользователя без его согласия.


Чтобы решить эту проблему и реализовать защиту от CSRF, вот пример соответствующего кода:



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
using System;
using System.Web.UI;

public partial class MyPage : Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        if (IsPostBack)
        {
            // Проверка маркера CSRF
            if (ValidateCsrfToken())
            {
                // Обработать запрос
                if (Request.QueryString["action"] == "delete")
                {
                    string id = Request.QueryString["id"];
                    // Delete the record with the given ID
                    // ...
                }
            }
            else
            {
                // Проверка токена CSRF не удалась, обработайте ошибку
                // ...
            }
        }
        else
        {
            // Генерируйте и храните маркер CSRF в состоянии сеанса или представления
            GenerateCsrfToken();
        }
    }

    private bool ValidateCsrfToken()
    {
        // Получение CSRF-токена из состояния сессии или представления
        string csrfToken = Session["CsrfToken"] as string;

        // Сравните CSRF-токен из запроса с хранимым токеном
        string requestToken = Request.Form["__RequestVerificationToken"];
        return csrfToken == requestToken;
    }

    private void GenerateCsrfToken()
    {
        // Генерируем уникальный CSRF-токен
        string csrfToken = Guid.NewGuid().ToString();

        // Сохраните CSRF-токен в состоянии сессии или представления
        Session["CsrfToken"] = csrfToken;

        // Включаем CSRF-токен в отрисованный HTML
        Page.ClientScript.RegisterHiddenField("__RequestVerificationToken", csrfToken);
    }
}
```


В соответствующем коде защита от CSRF реализована с помощью уникального CSRF-токена. Токен генерируется и хранится в состоянии сессии или представления при загрузке страницы. При последующих запросах маркер проверяется, чтобы убедиться, что запрос пришел с того же сайта, а не с сайта злоумышленника.

Реализуя защиту от CSRF, соответствующий код предотвращает несанкционированные действия, проверяя целостность запросов и гарантируя, что они исходят от легитимного пользователя. Это помогает защититься от CSRF-атак и повышает безопасность приложения.



Semgrep:


```
rules:
  - id: csrf-vulnerability
    patterns:
      - pattern: 'if \(Request\.QueryString\["action"\] == "delete"\)'
    message: "Potential CSRF vulnerability"
```

CodeQL:



```
import csharp

from MethodDeclaration method
where method.getName() = "Page_Load" and
  exists(BinaryExpression binaryExpr |
    binaryExpr.getOperator().toString() = "==" and
    binaryExpr.getLeftOperand().toString() = "Request.QueryString[\"action\"]" and
    binaryExpr.getRightOperand().toString() = "\"delete\""
  )
select method
```




## Использование жесткого пароля

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
using System;
using System.Data.SqlClient;

public class DatabaseConnector
{
    private string connectionString = "Server=myServerAddress;Database=myDatabase;User Id=myUsername;Password=myPassword;";

    public void Connect()
    {
        using (SqlConnection connection = new SqlConnection(connectionString))
        {
            // Подключение к базе данных
            connection.Open();
            // Выполняем операции с базой данных
            // ...
        }
    }
}
```

В этом несоответствующем коде строка подключения к базе данных содержит жестко закодированный пароль. Хранение такой конфиденциальной информации, как пароли, непосредственно в исходном коде представляет собой риск безопасности, поскольку пароль может быть легко обнаружен в случае доступа к коду или его утечки.


Чтобы решить эту проблему и реализовать более безопасный подход, приведем пример кода, соответствующего требованиям:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
using System;
using System.Configuration;
using System.Data.SqlClient;

public class DatabaseConnector
{
    private string connectionString = ConfigurationManager.ConnectionStrings["MyConnectionString"].ConnectionString;

    public void Connect()
    {
        using (SqlConnection connection = new SqlConnection(connectionString))
        {
            // Подключение к базе данных
            connection.Open();
            // Выполняем операции с базой данных
            // ...
        }
    }
}
```

В коде, соответствующем требованиям, пароль не хранится в исходном коде. Вместо этого он хранится в защищенном конфигурационном файле (например, web.config или app.config), а доступ к нему осуществляется с помощью класса ConfigurationManager. Файл конфигурации должен быть надлежащим образом защищен, а доступ к нему должен быть ограничен для авторизованного персонала.

Удалив жестко закодированный пароль и сохранив его в защищенном файле конфигурации, соответствующий код повышает безопасность приложения, предотвращая несанкционированный доступ к конфиденциальной информации.




Semgrep:


```
rules:
  - id: sensitive-information-exposure
    patterns:
      - pattern: 'private string connectionString = "Server=.+;Database=.+;User Id=.+;Password=.+;"'
    message: "Sensitive information exposure in database connection string"
```

CodeQL:



```
import csharp

from FieldDeclaration field
where field.getType().toString() = "System.String" and
  field.getInitializer().toString().indexOf("Server=") >= 0 and
  field.getInitializer().toString().indexOf("Database=") >= 0 and
  field.getInitializer().toString().indexOf("User Id=") >= 0 and
  field.getInitializer().toString().indexOf("Password=") >= 0
select field
```




## Нкенадёжный криптоалгоритм

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
using System;
using System.Security.Cryptography;

public class CryptoUtils
{
    public string Encrypt(string data, string key)
    {
        byte[] dataBytes = System.Text.Encoding.UTF8.GetBytes(data);
        byte[] keyBytes = System.Text.Encoding.UTF8.GetBytes(key);

        TripleDESCryptoServiceProvider desCryptoProvider = new TripleDESCryptoServiceProvider();
        desCryptoProvider.Key = keyBytes;
        desCryptoProvider.Mode = CipherMode.ECB; // Using ECB mode, which is insecure
        desCryptoProvider.Padding = PaddingMode.PKCS7;

        ICryptoTransform encryptor = desCryptoProvider.CreateEncryptor();
        byte[] encryptedData = encryptor.TransformFinalBlock(dataBytes, 0, dataBytes.Length);
        encryptor.Dispose();
        desCryptoProvider.Clear();

        return Convert.ToBase64String(encryptedData);
    }
}
```


В этом несоответствующем коде класс TripleDESCryptoServiceProvider используется с режимом ECB (Electronic Codebook), который, как известно, является небезопасным. Режим ECB не обеспечивает надлежащего шифрования, поскольку он шифрует каждый блок данных независимо, что приводит к потенциальным уязвимостям.


Чтобы решить эту проблему и использовать более безопасный криптографический алгоритм, вот пример соответствующего кода:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
using System;
using System.Security.Cryptography;

public class CryptoUtils
{
    public string Encrypt(string data, string key)
    {
        byte[] dataBytes = System.Text.Encoding.UTF8.GetBytes(data);
        byte[] keyBytes = System.Text.Encoding.UTF8.GetBytes(key);

        using (AesCryptoServiceProvider aesCryptoProvider = new AesCryptoServiceProvider())
        {
            aesCryptoProvider.Key = keyBytes;
            aesCryptoProvider.Mode = CipherMode.CBC;
            aesCryptoProvider.Padding = PaddingMode.PKCS7;

            ICryptoTransform encryptor = aesCryptoProvider.CreateEncryptor();
            byte[] encryptedData = encryptor.TransformFinalBlock(dataBytes, 0, dataBytes.Length);
            encryptor.Dispose();
            aesCryptoProvider.Clear();

            return Convert.ToBase64String(encryptedData);
        }
    }
}
```

В соответствующем коде класс AesCryptoServiceProvider используется с режимом CBC (Cipher Block Chaining), который является более безопасным, чем режим ECB. Кроме того, для обеспечения надлежащего управления ресурсами с помощью оператора using реализована надлежащая утилизация криптографических объектов.

Благодаря использованию такого безопасного криптографического алгоритма, как AES, в режиме CBC, соответствующий код повышает безопасность процесса шифрования, делая его устойчивым к известным криптографическим уязвимостям.





Semgrep:


```
rules:
  - id: insecure-encryption-mode
    patterns:
      - pattern: 'desCryptoProvider.Mode = CipherMode\.ECB'
    message: "Insecure encryption mode (ECB) detected"
```

CodeQL:



```
import csharp

from Assignment assignment
where assignment.getRightOperand().toString() = "CipherMode.ECB"
select assignment
```



## Insufficient Entropy

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
using System;

public class RandomNumberGenerator
{
    public int GenerateRandomNumber(int minValue, int maxValue)
    {
        Random random = new Random();
        return random.Next(minValue, maxValue);
    }
}
```


В этом несоответствующем коде для генерации случайных чисел используется класс Random из пространства имен System. Однако класс Random по умолчанию использует семя, основанное на времени, что может привести к предсказуемым и легко угадываемым случайным числам. Это происходит потому, что значение затравки основано на текущем системном времени, которое может быть легко определено или даже повторено, если код выполняется в течение короткого промежутка времени.



Чтобы решить эту проблему и повысить энтропию генерации случайных чисел, вот пример соответствующего кода:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
using System;
using System.Security.Cryptography;

public class RandomNumberGenerator
{
    public int GenerateRandomNumber(int minValue, int maxValue)
    {
        using (RNGCryptoServiceProvider rngCryptoProvider = new RNGCryptoServiceProvider())
        {
            byte[] randomBytes = new byte[4];
            rngCryptoProvider.GetBytes(randomBytes);
            int randomNumber = BitConverter.ToInt32(randomBytes, 0);

            return Math.Abs(randomNumber % (maxValue - minValue + 1)) + minValue;
        }
    }
}
```

В соответствующем коде для генерации случайных байтов с достаточной энтропией используется класс RNGCryptoServiceProvider из пространства имен System.Security.Cryptography. Затем эти случайные байты преобразуются в целое число с помощью метода BitConverter.ToInt32. Использование криптографического генератора случайных чисел обеспечивает более высокую степень энтропии и снижает предсказуемость генерируемых чисел.

Соответствующий код обеспечивает более безопасный механизм генерации случайных чисел, что делает его подходящим для приложений, требующих непредсказуемых и невоспроизводимых случайных значений.





Semgrep:


```
rules:
  - id: random-without-seed
    patterns:
      - pattern: 'new Random\(\)'
    message: "Random number generator initialized without a specified seed"
```

CodeQL:



```
import csharp

from ObjectCreation randomCreation, MethodAccess randomNextAccess
where randomCreation.getType().toString() = "System.Random" and
  randomNextAccess.getTarget().toString() = randomCreation.toString() and
  not exists(Expression seedArg |
    randomCreation.getArguments() = seedArg and
    seedArg.toString().startsWith("new Random(")
  )
select randomCreation
```



## XSS

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
using System;

public class UserInputProcessor
{
    public string ProcessUserInput(string userInput)
    {
        string sanitizedInput = userInput.Replace("<", "&lt;").Replace(">", "&gt;");
        return sanitizedInput;
    }
}
```

В этом несоответствующем коде метод ProcessUserInput пытается обеззаразить вводимые пользователем данные, заменяя символы < и > на соответствующие им HTML-сущности (&lt; и &gt;). Однако такой подход недостаточен для предотвращения XSS-атак, поскольку он фокусируется только на этих конкретных символах и не обрабатывает другие потенциально вредоносные данные.


Чтобы решить эту проблему и должным образом защитить от XSS-атак, вот пример соответствующего кода:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
using System;
using System.Web;

public class UserInputProcessor
{
    public string ProcessUserInput(string userInput)
    {
        string sanitizedInput = HttpUtility.HtmlEncode(userInput);
        return sanitizedInput;
    }
}
```


В коде, соответствующем требованиям, для правильного кодирования вводимых пользователем данных используется метод HtmlEncode из пространства имен System.Web. Этот метод заменяет специальные символы на соответствующие им HTML-сущности, гарантируя, что вводимые данные будут отображаться как обычный текст, а не интерпретироваться как HTML или JavaScript-код.

Благодаря использованию HtmlEncode совместимый код снижает риск XSS-атак, кодируя все потенциально опасные символы в пользовательском вводе, что позволяет безопасно отображать вводимые данные на веб-страницах без риска выполнения непредусмотренных сценариев.

Важно отметить, что наилучшим подходом к предотвращению XSS-атак является использование контекстного кодирования вывода на этапе рендеринга, а не полагаться только на санацию ввода. Это гарантирует, что выходные данные будут правильно закодированы в зависимости от контекста, в котором они используются, например атрибуты HTML, JavaScript или CSS, что обеспечивает надежную защиту от XSS-уязвимостей.





Semgrep:


```
rules:
  - id: xss-sanitization
    patterns:
      - pattern: 'Replace\(\"<\"'
    message: "Potential XSS vulnerability: User input not properly sanitized"
```

CodeQL:



```
import csharp

from MethodInvocation replaceMethod
where replaceMethod.getTarget().toString() = "userInput.Replace"
select replaceMethod
```




## SQL-инъекция

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
using System;
using System.Data.SqlClient;

public class UserLogin
{
    public bool AuthenticateUser(string username, string password)
    {
        string query = "SELECT COUNT(*) FROM Users WHERE Username='" + username + "' AND Password='" + password + "'";
        using (SqlConnection connection = new SqlConnection("Data Source=example.com;Initial Catalog=MyDB;User ID=sa;Password=pass123"))
        {
            SqlCommand command = new SqlCommand(query, connection);
            connection.Open();
            int count = (int)command.ExecuteScalar();
            return count > 0;
        }
    }
}
```

В этом несоответствующем коде метод AuthenticateUser строит SQL-запрос, непосредственно объединяя значения имени пользователя и пароля в строке запроса. Такой подход очень уязвим для атак SQL-инъекций, поскольку злоумышленник может манипулировать вводом данных для выполнения произвольных SQL-команд.


Чтобы предотвратить атаки SQL-инъекций и обеспечить безопасное взаимодействие с базой данных, вот пример соответствующего кода:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
using System;
using System.Data.SqlClient;

public class UserLogin
{
    public bool AuthenticateUser(string username, string password)
    {
        string query = "SELECT COUNT(*) FROM Users WHERE Username=@Username AND Password=@Password";
        using (SqlConnection connection = new SqlConnection("Data Source=example.com;Initial Catalog=MyDB;User ID=sa;Password=pass123"))
        {
            SqlCommand command = new SqlCommand(query, connection);
            command.Parameters.AddWithValue("@Username", username);
            command.Parameters.AddWithValue("@Password", password);
            connection.Open();
            int count = (int)command.ExecuteScalar();
            return count > 0;
        }
    }
}
```

В соответствующем коде для безопасной обработки пользовательского ввода используются параметризованные запросы. Строка запроса содержит заполнители (@Username и @Password) для вводимых значений. Фактические значения затем предоставляются с помощью метода AddWithValue объекта SqlCommand, который добавляет значения в качестве параметров, а не конкатенирует их непосредственно в запрос.

Благодаря использованию параметризованных запросов соответствующий код гарантирует, что пользовательский ввод будет рассматриваться как данные, а не как исполняемый код, что эффективно предотвращает атаки SQL-инъекций. Движок базы данных обеспечивает надлежащее экранирование и дезинфекцию вводимых значений, обеспечивая безопасность приложения.




Semgrep:


```
rules:
  - id: sql-injection
    patterns:
      - pattern: 'SELECT .* FROM .* WHERE .*'
    message: "Potential SQL injection vulnerability: User input not properly parameterized"
```

CodeQL:



```
import csharp

from BinaryExpression binaryExpr
where binaryExpr.getLeftOperand().toString().startsWith("\"SELECT ") and
  binaryExpr.getOperator().toString() = "+" and
  binaryExpr.getRightOperand().toString().contains("\"")
select binaryExpr
```



## Внешнее управление именем или путем файла

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
using System;
using System.IO;

public class FileProcessor
{
    public void ProcessFile(string fileName)
    {
        string filePath = "C:\\Temp\\" + fileName;
        if (File.Exists(filePath))
        {
            // Обработка файла
        }
        else
        {
            Console.WriteLine("File not found.");
        }
    }
}
```


In this noncompliant code, the ProcessFile method constructs the file path by directly concatenating the fileName parameter with a fixed base directory (C:\Temp\). This approach is vulnerable to external control of the file name, as an attacker can manipulate the fileName input to access files outside the intended directory.


To prevent external control of file name or path attacks and ensure secure file operations, here's an example of compliant code:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
using System;
using System.IO;

public class FileProcessor
{
    private readonly string baseDirectory = "C:\\Temp\\";

    public void ProcessFile(string fileName)
    {
        string sanitizedFileName = Path.GetFileName(fileName);
        string filePath = Path.Combine(baseDirectory, sanitizedFileName);
        if (File.Exists(filePath))
        {
            // Обработка файла
        }
        else
        {
            Console.WriteLine("File not found.");
        }
    }
}
```

В соответствующем коде метод Path.GetFileName используется для извлечения имени файла из параметра fileName, отбрасывая любую информацию о каталоге. Затем используется метод Path.Combine для построения полного пути к файлу путем объединения базового каталога (C:\Temp\) и дезинфицированного имени файла.

Используя эти методы безопасной обработки пути к файлу, соответствующий код гарантирует, что имя файла или путь к нему, указанные пользователем, будут должным образом проверены, и предотвращает несанкционированный доступ к файлам за пределами предполагаемого каталога.






Semgrep:


```
rules:
  - id: path-traversal
    patterns:
      - pattern: 'C:\\Temp\\\\'
    message: "Potential path traversal vulnerability: Unsanitized file path concatenation"
```

CodeQL:



```
import csharp

from Addition addExpr
where addExpr.getLeftOperand().toString() = "\"C:\\Temp\\" and
  addExpr.getOperator().toString() = "+" and
  addExpr.getRightOperand().toString().contains("\"")
select addExpr
```



## Формирование сообщения об ошибке, содержащего конфиденциальную информацию

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
using System;

public class UserController
{
    public void AuthenticateUser(string username, string password)
    {
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
        {
            throw new ArgumentException("Invalid username or password.");
        }

        // Аутентификация пользователя
    }
}
```


В этом несоответствующем коде, когда метод AuthenticateUser получает пустое или нулевое имя пользователя или пароль, он выбрасывает ArgumentException с сообщением об ошибке, раскрывающим конфиденциальную информацию ("Invalid username or password"). Раскрытие такой информации в сообщениях об ошибках может помочь злоумышленникам определить правильные имена пользователей и, возможно, начать дальнейшие атаки.


Чтобы решить эту проблему и предотвратить раскрытие конфиденциальной информации, приведем пример соответствующего кода:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
using System;

public class UserController
{
    public void AuthenticateUser(string username, string password)
    {
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
        {
            throw new ArgumentException("Invalid credentials.");
        }

        // Аутентификация пользователя
    }
}
```

В соответствующем коде сообщение об ошибке было обобщено до "Неверные учетные данные", вместо того чтобы явно указывать имя пользователя или пароль. Такой подход позволяет избежать раскрытия конфиденциальной информации в сообщениях об ошибках, что затрудняет злоумышленникам сбор полезной информации.

Следуя этому подходу, соответствующий код гарантирует, что сообщения об ошибках не раскрывают конфиденциальную информацию, тем самым снижая риск потенциальных атак, направленных на учетные данные пользователя.





Semgrep:


```
rules:
  - id: empty-username-password
    patterns:
      - pattern: 'string.IsNullOrEmpty\({{ _ }}\)'
    message: "Potential issue: Empty or null username or password"
```

CodeQL:



```
import csharp

from Invocation invocation
where invocation.getTarget().toString() = "string.IsNullOrEmpty" and
  invocation.getArgument(0).toString() = "{{ _ }}"
select invocation
```


## незащищенное хранение учетных данных

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
using System;

public class UserController
{
    private string _username;
    private string _password;

    public void SetCredentials(string username, string password)
    {
        _username = username;
        _password = password;
    }

    public void AuthenticateUser()
    {
        // Аутентификация пользователя с помощью сохраненных учетных данных
    }
}
```

В этом несоответствующем коде метод SetCredentials хранит имя пользователя и пароль, предоставленные пользователем, в переменных уровня класса `_username` и `_password`, соответственно. Однако эти учетные данные хранятся в виде обычного текста без какой-либо дополнительной защиты, например, шифрования или механизмов безопасного хранения. Это делает конфиденциальную информацию уязвимой для несанкционированного доступа, если злоумышленник получит доступ к приложению или системе.


Чтобы решить эту проблему безопасности и обеспечить защищенное хранение учетных данных, приведем пример соответствующего кода:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
using System;
using System.Security.Cryptography;

public class UserController
{
    private byte[] _encryptedCredentials;

    public void SetCredentials(string username, string password)
    {
        byte[] encryptedUsername = EncryptData(username);
        byte[] encryptedPassword = EncryptData(password);

        _encryptedCredentials = CombineArrays(encryptedUsername, encryptedPassword);
    }

    public void AuthenticateUser()
    {
        // Расшифруйте и используйте сохраненные учетные данные для аутентификации пользователя
        string decryptedUsername = DecryptData(GetUsernameFromEncryptedCredentials());
        string decryptedPassword = DecryptData(GetPasswordFromEncryptedCredentials());

        // Аутентификация пользователя с использованием расшифрованных учетных данных
    }

    private byte[] EncryptData(string data)
    {
        // Используем безопасный алгоритм шифрования (например, AES) для шифрования данных
        // и возвращает зашифрованный массив байтов
        // ...
    }

    private string DecryptData(byte[] encryptedData)
    {
        // Используйте тот же алгоритм шифрования и процесс дешифрования.
        // для расшифровки данных и возврата открытого текста
        // ...
    }

    private byte[] CombineArrays(byte[] array1, byte[] array2)
    {
        // Объединить два массива байтов в один
        // ...
    }

    private byte[] GetUsernameFromEncryptedCredentials()
    {
        // Извлекаем и возвращаем зашифрованное имя пользователя из сохраненных учетных данных
        // ...
    }

    private byte[] GetPasswordFromEncryptedCredentials()
    {
        // Извлечение и возврат зашифрованного пароля из хранящихся учетных данных
        // ...
    }
}
```

В соответствующем коде конфиденциальная информация (имя пользователя и пароль) больше не хранится в виде обычного текста. Вместо этого метод SetCredentials шифрует имя пользователя и пароль с помощью безопасного алгоритма шифрования (например, AES), а затем сохраняет их в переменной _encryptedCredentials. Затем метод AuthenticateUser извлекает и расшифровывает учетные данные для целей аутентификации.


Шифруя учетные данные, соответствующий код гарантирует, что даже если злоумышленник получит несанкционированный доступ к хранящимся учетным данным, они будут находиться в зашифрованном виде, что значительно снижает риск раскрытия конфиденциальной информации.




Semgrep:


```
rules:
  - id: insecure-credentials-storage
    patterns:
      - pattern: '_username = {{ _ }}'
      - pattern: '_password = {{ _ }}'
    message: "Potential security issue: Credentials stored in memory"
```

CodeQL:



```
import csharp

class StoredCredentials extends FieldAccess {
  StoredCredentials() {
    this.getTarget().toString().matches("_username") or
    this.getTarget().toString().matches("_password")
  }
}

from StoredCredentials access
select access
```


## Нарушение границ доверия

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
using System;

public class PaymentController
{
    private string _creditCardNumber;

    public void ProcessPayment(string creditCardNumber)
    {
        _creditCardNumber = creditCardNumber;
        // Обработка платежа по номеру кредитной карты
    }
}
```

В этом коде, не соответствующем требованиям, метод ProcessPayment принимает номер кредитной карты в качестве параметра и напрямую сохраняет его в переменной _creditCardNumber в классе PaymentController. Номер кредитной карты рассматривается как доверенные данные внутри класса, даже если он получен из внешнего источника. Это нарушает границу доверия, предполагая, что данные безопасны и заслуживают доверия, что может привести к потенциальным уязвимостям безопасности.


Чтобы решить эту проблему безопасности и обеспечить надлежащую границу доверия, вот пример соответствующего кода:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
using System;

public class PaymentController
{
    public void ProcessPayment(string creditCardNumber)
    {
        // Выполните проверку ввода и санацию номера кредитной карты
        if (IsValidCreditCardNumber(creditCardNumber))
        {
            // Обработайте платеж, используя номер кредитной карты
        }
        else
        {
            // Обработка случая, когда предоставлен недействительный номер кредитной карты
        }
    }

    private bool IsValidCreditCardNumber(string creditCardNumber)
    {
        // Реализуем надлежащую логику проверки номера кредитной карты
        // чтобы убедиться, что вводимые данные соответствуют требуемому формату и целостности
        // ...
    }
}
```


В соответствующем коде метод ProcessPayment выполняет проверку ввода и санацию номера кредитной карты перед обработкой платежа. Метод проверяет, является ли номер кредитной карты действительным, вызывая функцию IsValidCreditCardNumber, которая реализует необходимую логику проверки, чтобы убедиться, что вводимые данные соответствуют требуемому формату и целостности.

Реализуя надлежащую проверку и санацию ввода, соответствующий код устанавливает границу доверия и гарантирует, что обрабатываются только достоверные и проверенные данные, снижая риск возникновения уязвимостей безопасности из-за недоверенного или вредоносного ввода.





Semgrep:


```
rules:
  - id: insecure-credit-card-storage
    patterns:
      - pattern: '_creditCardNumber = {{ _ }}'
    message: "Potential security issue: Credit card number stored in memory"
```

CodeQL:



```
import csharp

class StoredCreditCardNumber extends FieldAccess {
  StoredCreditCardNumber() {
    this.getTarget().toString().matches("_creditCardNumber")
  }
}

from StoredCreditCardNumber access
select access
```



## Недостаточно защищенные учетные данные

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
using System;

public class LoginController
{
    private string _username;
    private string _password;

    public bool Authenticate(string username, string password)
    {
        _username = username;
        _password = password;
        
        // Выполните логику аутентификации
        // ...
        
        return true;
    }
}
```

В этом коде, не соответствующем требованиям, метод Authenticate принимает имя пользователя и пароль в качестве параметров и напрямую сохраняет их в переменных _username и _password в классе LoginController. Учетные данные хранятся в виде обычного текста без каких-либо дополнительных механизмов защиты, таких как шифрование или хеширование. Хранение учетных данных в открытом тексте повышает риск несанкционированного доступа и потенциальной утечки данных в случае их компрометации.

Чтобы решить эту проблему безопасности и обеспечить надлежащую защиту учетных данных, вот пример соответствующего кода:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
using System;
using System.Security.Cryptography;

public class LoginController
{
    public bool Authenticate(string username, string password)
    {
        string hashedPassword = HashPassword(password);
        
        // Выполните логику аутентификации, используя хэшированный пароль
        // ...
        
        return true;
    }

    private string HashPassword(string password)
    {
        using (SHA256 sha256 = SHA256.Create())
        {
            byte[] passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);
            byte[] hashedBytes = sha256.ComputeHash(passwordBytes);
            return Convert.ToBase64String(hashedBytes);
        }
    }
}
```


В соответствующем коде метод Authenticate по-прежнему принимает имя пользователя и пароль в качестве параметров, но вместо того, чтобы хранить их напрямую, пароль хэшируется с помощью безопасной криптографической хэш-функции (в данном случае SHA-256). Функция HashPassword принимает пароль на вход, генерирует хэш-значение и возвращает хэшированный пароль в виде строки.


Хеширование пароля позволяет совместимому коду гарантировать, что учетные данные не хранятся в виде обычного текста, и добавляет дополнительный уровень защиты. При аутентификации хранящийся хэшированный пароль сравнивается с хэшированной версией введенного пользователем пароля, а не сравниваются непосредственно пароли в открытом тексте.

Использование правильных методов хеширования паролей помогает снизить последствия утечки данных и несанкционированного доступа, поскольку даже если хранящиеся хеши получены, их вычислительно сложно вернуть к исходному паролю.






Semgrep:


```
rules:
  - id: insecure-sensitive-data-storage
    patterns:
      - pattern: '_username = {{ _ }}'
      - pattern: '_password = {{ _ }}'
    message: "Potential security issue: Sensitive data stored in memory"
```

CodeQL:



```
rules:
  - id: insecure-sensitive-data-storage
    patterns:
      - pattern: '_username = {{ _ }}'
      - pattern: '_password = {{ _ }}'
    message: "Potential security issue: Sensitive data stored in memory"
```




## Restriction of XML External Entity Reference

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
using System;
using System.Xml;

public class XmlParser
{
    public void ParseXml(string xmlContent)
    {
        XmlDocument xmlDoc = new XmlDocument();
        xmlDoc.LoadXml(xmlContent);
        
        // Обработка XML-документа
        // ...
    }
}
```

В этом несовместимом коде метод ParseXml принимает XML-содержимое в виде строки и загружает его в объект XmlDocument с помощью метода LoadXml. Однако в этом коде не предусмотрено никаких ограничений на ссылки на внешние сущности, что делает его уязвимым для XXE-атак.


Чтобы решить эту проблему безопасности и ограничить ссылки на внешние сущности XML, вот пример соответствующего кода:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
using System;
using System.Xml;

public class XmlParser
{
    public void ParseXml(string xmlContent)
    {
        XmlReaderSettings settings = new XmlReaderSettings();
        settings.DtdProcessing = DtdProcessing.Prohibit;

        using (XmlReader reader = XmlReader.Create(new System.IO.StringReader(xmlContent), settings))
        {
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.Load(reader);

            // Обработка XML-документа
            // ...
        }
    }
}
```


В соответствующем коде метод ParseXml создает экземпляр XmlReaderSettings и явно устанавливает свойство DtdProcessing в DtdProcessing.Prohibit. Эта настройка предотвращает разбор любых внешних сущностей, определенных в XML-содержимом, эффективно защищая от XXE-атак.


Применяя это ограничение, соответствующий код гарантирует, что разбор XML выполняется без оценки ссылок на внешние сущности, тем самым защищаясь от потенциальных атак, использующих уязвимости XXE.






Semgrep:


```
rules:
  - id: xml-parsing-insecure
    pattern: |
      XmlDocument xmlDoc = new XmlDocument();
      xmlDoc.LoadXml({{ _ }});
    message: "Potential security issue: Insecure XML parsing"
```

CodeQL:



```
import csharp

class InsecureXmlParsing extends MethodCall {
  InsecureXmlParsing() {
    this.getTarget().toString().matches("XmlDocument.LoadXml")
  }
}

from InsecureXmlParsing call
select call
```



## Уязвимые и устаревшие компоненты


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
using System;
using Newtonsoft.Json;

public class UserData
{
    public string Name { get; set; }
    public string Email { get; set; }
}

public class UserController
{
    public void GetUserDetails()
    {
        // Получение данных о пользователе из базы данных
        UserData user = Database.GetUserDetails();

        // Конвертируем данные пользователя в JSON
        string json = JsonConvert.SerializeObject(user);

        // Отправляем JSON-ответ клиенту
        HttpResponse.Write(json);
    }
}
```

В этом коде, не соответствующем требованиям, UserController получает данные пользователя из базы данных и преобразует их в JSON с помощью метода JsonConvert.SerializeObject из библиотеки Newtonsoft.Json. Однако в коде используется устаревшая версия библиотеки, которая может содержать известные уязвимости.


Чтобы решить эту проблему безопасности и обеспечить использование безопасных и актуальных компонентов, вот пример соответствующего кода:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
using System;
using System.Text.Json;

public class UserData
{
    public string Name { get; set; }
    public string Email { get; set; }
}

public class UserController
{
    public void GetUserDetails()
    {
        // Получение данных о пользователе из базы данных
        UserData user = Database.GetUserDetails();

        // Конвертируем данные пользователя в JSON
        string json = JsonSerializer.Serialize(user);

        // Отправляем JSON-ответ клиенту
        HttpResponse.Write(json);
    }
}
```


В соответствующем коде UserController использует встроенное пространство имен System.Text.Json вместо библиотеки Newtonsoft.Json. Используя последнюю версию встроенного JSON-сериализатора, код обеспечивает использование безопасных и актуальных компонентов.


Очень важно регулярно обновлять и заменять уязвимые или устаревшие компоненты их последними версиями или более безопасными альтернативами, чтобы снизить потенциальные риски безопасности.





Semgrep:


```
rules:
  - id: json-serialization-insecure
    pattern: |
      JsonConvert.SerializeObject({{ _ }});
    message: "Potential security issue: Insecure JSON serialization"
```

CodeQL:



```
import csharp

class InsecureJsonSerialization extends MethodCall {
  InsecureJsonSerialization() {
    this.getTarget().toString().matches("JsonConvert.SerializeObject")
  }
}

from InsecureJsonSerialization call
select call
```



## Неправильная проверка сертификата с несоответствием хоста

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
using System;
using System.Net.Http;

public class HttpClientExample
{
    public void SendRequest()
    {
        // Создание экземпляра HttpClient
        HttpClient client = new HttpClient();

        // Отключаем проверку SSL-сертификата
        ServicePointManager.ServerCertificateValidationCallback +=
            (sender, certificate, chain, sslPolicyErrors) => true;

        // Отправляем запрос на удаленный сервер
        HttpResponseMessage response = client.GetAsync("https://example.com").Result;

        // Обрабатываем ответ
        if (response.IsSuccessStatusCode)
        {
            // Сделайте что-нибудь с успешным ответом
            Console.WriteLine("Запрос прошел успешно!");
        }
        else
        {
            // Обработать ответ об ошибке
            Console.WriteLine("Request failed!");
        }
    }
}
```

В этом несоответствующем коде класс HttpClientExample отправляет запрос на удаленный сервер с помощью класса HttpClient. Однако код отключает проверку сертификата SSL, изменяя событие ServicePointManager.ServerCertificateValidationCallback так, чтобы оно всегда возвращало true. Это означает, что код примет любой сертификат, даже если он не соответствует хосту, просрочен или имеет другие проблемы с безопасностью.


Чтобы решить эту проблему безопасности и обеспечить правильную проверку сертификатов с совпадением хоста, вот пример соответствующего кода:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
using System;
using System.Net.Http;

public class HttpClientExample
{
    public void SendRequest()
    {
        // Создание экземпляра HttpClient
        HttpClient client = new HttpClient();

        // Включите проверку SSL-сертификата
        ServicePointManager.ServerCertificateValidationCallback +=
            (sender, certificate, chain, sslPolicyErrors) =>
            {
                if (sslPolicyErrors == SslPolicyErrors.None)
                    return true;
                
                // Проверяем, соответствует ли сертификат хосту
                string requestedHost = new Uri("https://example.com").Host;
                return certificate.Subject.Equals($"CN={requestedHost}", StringComparison.OrdinalIgnoreCase);
            };

        // Отправляем запрос на удаленный сервер
        HttpResponseMessage response = client.GetAsync("https://example.com").Result;

        // Обрабатываем ответ
        if (response.IsSuccessStatusCode)
        {
            // Сделайте что-нибудь с успешным ответом
            Console.WriteLine("Запрос прошел успешно!");
        }
        else
        {
            // Обрабатываем ответ об ошибке
            Console.WriteLine("Запрос не удался!");
        }
    }
}
```


В соответствующем коде событие ServicePointManager.ServerCertificateValidationCallback модифицировано для выполнения надлежащей проверки сертификата. Оно проверяет, совпадает ли тема сертификата с запрашиваемым хостом, гарантируя, что сертификат действителен и не подвержен уязвимостям несоответствия хоста.

Благодаря правильной проверке сертификатов с совпадением хоста соответствующий код снижает риск атак типа "человек посередине" и других уязвимостей безопасности, связанных с неправильной проверкой сертификатов.




Semgrep:


```
rules:
  - id: disable-ssl-certificate-validation
    pattern: |
      ServicePointManager.ServerCertificateValidationCallback += {{ _ }};
    message: "Potential security issue: Disabling SSL certificate validation"
```

CodeQL:



```
import csharp

class DisableSSLCertificateValidation extends MethodCall {
  DisableSSLCertificateValidation() {
    this.getTarget().toString().matches("ServicePointManager.ServerCertificateValidationCallback +=")
  }
}

from DisableSSLCertificateValidation call
select call
```





## Неправильная аутентификация

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
using System;
using System.Data.SqlClient;

public class AuthenticationExample
{
    public bool AuthenticateUser(string username, string password)
    {
        string connectionString = "Data Source=...;Initial Catalog=...;User ID=...;Password=...";

        // Создайте SQL-запрос, используя данные, предоставленные пользователем
        string query = $"SELECT * FROM Users WHERE Username = '{username}' AND Password = '{password}'";

        using (SqlConnection connection = new SqlConnection(connectionString))
        {
            SqlCommand command = new SqlCommand(query, connection);

            // Открываем соединение
            connection.Open();

            // Выполняем запрос
            SqlDataReader reader = command.ExecuteReader();

            // Проверяем, существует ли пользователь
            bool userExists = reader.HasRows;

            // Закрываем соединение
            connection.Close();

            return userExists;
        }
    }
}
```

В этом несоответствующем коде метод AuthenticateUser выполняет аутентификацию путем построения SQL-запроса с введенными пользователем именем пользователя и паролем. Этот код подвержен атакам SQL-инъекций, поскольку пользовательский ввод непосредственно конкатенируется в строку запроса без надлежащей санации или параметризации.


Чтобы решить эту проблему безопасности и обеспечить надлежащую аутентификацию, вот пример совместимого кода, в котором используются параметризованные запросы:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
using System;
using System.Data.SqlClient;

public class AuthenticationExample
{
    public bool AuthenticateUser(string username, string password)
    {
        string connectionString = "Data Source=...;Initial Catalog=...;User ID=...;Password=...";

        // Создайте параметризованный SQL-запрос
        string query = "SELECT * FROM Users WHERE Username = @username AND Password = @password";

        using (SqlConnection connection = new SqlConnection(connectionString))
        {
            SqlCommand command = new SqlCommand(query, connection);

            // Добавляем параметры в команду
            command.Parameters.AddWithValue("@username", username);
            command.Parameters.AddWithValue("@password", password);

            // Открываем соединение
            connection.Open();

            // Выполнение запроса
            SqlDataReader reader = command.ExecuteReader();

            // Проверяем, существует ли пользователь
            bool userExists = reader.HasRows;

            // Закрываем соединение
            connection.Close();

            return userExists;
        }
    }
}
```


В соответствующем коде SQL-запрос параметризован, и пользовательский ввод передается в качестве параметров объекту SqlCommand. Это обеспечивает правильную обработку входных данных и предотвращает атаки SQL-инъекций, поскольку входные данные рассматриваются как данные, а не как исполняемый код.

Благодаря использованию параметризованных запросов совместимый код снижает риск SQL-инъекций и обеспечивает надлежащую аутентификацию пользователей.





Semgrep:


```
rules:
  - id: sql-injection
    pattern: |
      SqlCommand command = new SqlCommand({{ query }}, {{ connection }});
    message: "Potential SQL injection vulnerability"
```

CodeQL:



```
import csharp

class SQLInjection extends MethodCall {
  SQLInjection() {
    this.getTarget().toString().matches("SqlCommand SqlCommand(SqlConnection, String)")
    or
    this.getTarget().toString().matches("SqlCommand SqlCommand(SqlConnection, String, SqlConnection)")
  }
}

from SQLInjection call, DataFlow::PathNode query
where query.asExpr().getValue().toString().matches(".*[\"'].*")
select query, call
```




## Фиксация сеанса

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
using System;
using System.Web;

public class SessionFixationExample
{
    public void Login(string username)
    {
        // Создайте новую сессию
        HttpSessionState session = HttpContext.Current.Session;

        // Устанавливаем имя пользователя в сессии
        session["username"] = username;
    }

    public bool IsUserAuthenticated()
    {
        // Получаем сессию
        HttpSessionState session = HttpContext.Current.Session;

        // Проверяем, существует ли имя пользователя в сессии
        return session["username"] != null;
    }
}
```

В этом коде, не соответствующем требованиям, метод Login создает новую сессию и устанавливает имя пользователя, указанное пользователем. Однако идентификатор сеанса остается неизменным на протяжении всей сессии пользователя, что делает его уязвимым для атак с фиксацией сеанса. Злоумышленник может заставить пользователя использовать определенный идентификатор сессии, что потенциально может скомпрометировать сессию пользователя.


Чтобы решить эту проблему безопасности и предотвратить атаки с фиксацией сеанса, приведем пример соответствующего кода, который регенерирует идентификатор сеанса после успешной аутентификации:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
using System;
using System.Web;

public class SessionFixationExample
{
    public void Login(string username)
    {
        // Создайте новую сессию
        HttpSessionState session = HttpContext.Current.Session;

        // Устанавливаем имя пользователя в сессии
        session["username"] = username;

        // Регенерируем идентификатор сессии
        session.RegenerateID();
    }

    public bool IsUserAuthenticated()
    {
        // Получение сессии
        HttpSessionState session = HttpContext.Current.Session;

        // Проверяем, существует ли имя пользователя в сессии
        return session["username"] != null;
    }
}
```


В соответствующем коде после установки имени пользователя в сессии идентификатор сессии регенерируется с помощью метода RegenerateID. Это гарантирует, что после успешной аутентификации будет сгенерирован новый идентификатор сеанса, что эффективно предотвращает атаки с фиксацией сеанса.

Благодаря регенерации идентификатора сеанса код, соответствующий требованиям, снижает риск фиксации сеанса и гарантирует, что каждому пользователю при аутентификации будет присвоен уникальный идентификатор сеанса.





Semgrep:


```
rules:
  - id: session-fixation
    pattern: |
      HttpSessionState session = HttpContext.Current.Session;
    message: "Potential session fixation vulnerability"
```

CodeQL:



```
import csharp

class SessionFixation extends MethodAccess {
  SessionFixation() {
    this.getTarget().toString().matches("HttpSessionState HttpSessionState(HttpContext)")
  }
}

from SessionFixation call, DataFlow::PathNode session
select session, call
```


## Включение функциональности из недоверенного управления

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
using System;
using System.Diagnostics;
using System.IO;

public class FileUploader
{
    public void UploadFile(string filename, byte[] fileData)
    {
        // Сохраните загруженный файл в указанную директорию
        string savePath = "C:\\\Uploads\\\\" + filename;
        File.WriteAllBytes(savePath, fileData);
        
        // Выполнение команды над загруженным файлом
        string command = "C:\\Windows\\System32\\cmd.exe /C echo File uploaded successfully!";
        Process.Start(command, savePath);
    }
}
```

В этом коде, не соответствующем требованиям, метод UploadFile принимает на вход имя файла и соответствующие ему данные. Файл сохраняется в указанную директорию без надлежащей проверки или санитарной обработки. После сохранения файла выполняется команда над загруженным файлом с помощью Process.Start. Этот код уязвим для выполнения произвольного кода, так как злоумышленник может загрузить вредоносный файл и выполнить произвольные команды на сервере.


Чтобы решить эту проблему безопасности и предотвратить включение функциональности из ненадежного управления, вот пример совместимого кода, который ограничивает выполнение загруженного файла:







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
using System;
using System.Diagnostics;
using System.IO;

public class FileUploader
{
    public void UploadFile(string filename, byte[] fileData)
    {
        // Проверяем и обеззараживаем имя файла
        string sanitizedFilename = SanitizeFilename(filename);
        if (sanitizedFilename == null)
        {
            // Неверное имя файла, прервать загрузку
            return;
        }

        // Сохраняем загруженный файл в указанную директорию
        string savePath = "C:\\\Uploads\\\\" + sanitizedFilename;
        File.WriteAllBytes(savePath, fileData);
        
        // Выполняем другие операции с загруженным файлом (например, ведение журнала, проверка на вирусы)

        // Уведомить пользователя об успешной загрузке
        Console.WriteLine("File uploaded successfully!");
    }

    private string SanitizeFilename(string filename)
    {
        // Реализуйте надлежащую логику проверки и санации имен файлов.
        // Убедитесь, что имя файла соответствует требуемому формату и не содержит вредоносных символов или последовательностей обхода путей
        
        // Пример реализации: удаление любой информации о пути и запрет определенных символов
        string sanitizedFilename = Path.GetFileName(filename);
        if (sanitizedFilename.IndexOfAny(Path.GetInvalidFileNameChars()) != -1)
        {
            // Неверное имя файла, возвращаем null
            return null;
        }

        return sanitizedFilename;
    }
}
```


В совместимом коде было сделано несколько улучшений для обеспечения безопасности функции загрузки файлов. Имя файла проверяется и обеззараживается с помощью метода SanitizeFilename, который удаляет любую информацию о пути и запрещает определенные символы. Если имя файла считается недействительным или содержит вредоносное содержимое, загрузка прерывается.

Кроме того, код больше не выполняет произвольные команды над загруженным файлом. Вместо этого он выполняет другие необходимые операции, такие как ведение журнала или проверка на вирусы. Наконец, пользователь получает уведомление об успешной загрузке, не подвергая сервер потенциальным рискам безопасности.




Semgrep:


```
rules:
  - id: directory-traversal
    pattern: File.WriteAllBytes($savePath, $fileData)
    message: "Potential directory traversal vulnerability when saving file"
```

CodeQL:



```
rules:
  - id: directory-traversal
    pattern: File.WriteAllBytes($savePath, $fileData)
    message: "Potential directory traversal vulnerability when saving file"
```



## Загрузка кода без проверки целостности

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
using System;
using System.Net;

public class CodeDownloader
{
    public void DownloadCode(string url)
    {
        using (WebClient client = new WebClient())
        {
            string code = client.DownloadString(url);
            
            // Выполнение загруженного кода
            ExecuteCode(code);
        }
    }

    private void ExecuteCode(string code)
    {
        // Выполнение загруженного кода без проверки целостности
        Console.WriteLine("Executing downloaded code: " + code);
        // ...
    }
}
```

В этом коде, не соответствующем требованиям, метод DownloadCode загружает код с указанного URL с помощью класса WebClient. Как только код загружен, он немедленно выполняется без проверки целостности или валидации. Такой подход создает риск выполнения вредоносного или недоверенного кода, что может привести к возникновению уязвимостей в системе безопасности и ее компрометации.


Чтобы решить эту проблему безопасности и обеспечить целостность загружаемого кода, приведем пример совместимого кода, включающего проверку целостности:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
using System;
using System.Net;
using System.Security.Cryptography;
using System.Text;

public class CodeDownloader
{
    public void DownloadCode(string url)
    {
        using (WebClient client = new WebClient())
        {
            byte[] downloadedData = client.DownloadData(url);
            
            // Проверяем целостность загруженного кода
            if (IsCodeIntegrityValid(downloadedData))
            {
                string code = Encoding.UTF8.GetString(downloadedData);
                
                // Выполняем загруженный код
                ExecuteCode(code);
            }
            else
            {
                Console.WriteLine("Code integrity check failed. Aborting execution.");
            }
        }
    }

    private bool IsCodeIntegrityValid(byte[] downloadedData)
    {
        // Реализуйте здесь логику проверки целостности.
        // Например, вычислите хэш загруженного кода и сравните его с доверенным хэш-значением
        
        using (SHA256 sha256 = SHA256.Create())
        {
            byte[] hash = sha256.ComputeHash(downloadedData);

            // Сравниваем вычисленный хэш с доверенным хэш-значением
            byte[] trustedHash = GetTrustedHash(); // Retrieve the trusted hash value from a secure source

            return ByteArrayEquals(hash, trustedHash);
        }
    }

    private bool ByteArrayEquals(byte[] array1, byte[] array2)
    {
        // Сравните два массива байтов на равенство
        if (array1.Length != array2.Length)
            return false;

        for (int i = 0; i < array1.Length; i++)
        {
            if (array1[i] != array2[i])
                return false;
        }

        return true;
    }

    private void ExecuteCode(string code)
    {
        // Выполнение загруженного кода
        Console.WriteLine("Выполнение загруженного кода: " + код);
        // ...
    }
}
```


В соответствующем коде реализованы дополнительные меры для обеспечения целостности загружаемого кода. Метод DownloadData используется вместо DownloadString для получения кода в виде массива байт. Метод IsCodeIntegrityValid вычисляет хэш загруженного кода с помощью безопасного алгоритма хэширования (в данном примере SHA-256) и сравнивает его с доверенным хэш-значением, полученным из безопасного источника.

Если проверка целостности пройдена, код преобразуется в строку и затем выполняется. В противном случае, если проверка целостности провалена, выполнение кода прерывается. Такой подход гарантирует, что может быть выполнен только код с достоверной целостностью, что снижает риск загрузки и выполнения вредоносного или поддельного кода.





Semgrep:


```
rules:
  - id: insecure-code-download
    pattern: WebClient().DownloadString($url)
    message: "Potential security risk: Insecure code download"
```

CodeQL:



```
import csharp

class CodeDownload extends MethodCall {
  CodeDownload() {
    this.getTarget().toString().matches("WebClient().DownloadString($url)")
  }
}

from CodeDownload
select CodeDownload
```


## Десериализация недоверенных данных

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

public class DataDeserializer
{
    public object DeserializeData(byte[] data)
    {
        BinaryFormatter formatter = new BinaryFormatter();
        MemoryStream memoryStream = new MemoryStream(data);
        
        // Десериализуйте недоверенные данные
        object deserializedData = formatter.Deserialize(memoryStream);
        
        return deserializedData;
    }
}
```

В этом несоответствующем коде метод DeserializeData десериализует предоставленные данные byte[] с помощью класса BinaryFormatter, не выполняя никакой проверки достоверности или безопасности. Десериализация недоверенных данных без надлежащей проверки может привести к серьезным уязвимостям безопасности, включая удаленное выполнение кода и атаки с внедрением объектов.


Чтобы решить эту проблему безопасности и обеспечить безопасную десериализацию данных, приведем пример соответствующего кода:





Semgrep:


```
rules:
  - id: insecure-data-deserialization
    pattern: BinaryFormatter().Deserialize($stream)
    message: "Potential security risk: Insecure data deserialization"
```

CodeQL:



```
import csharp

class DataDeserialization extends MethodCall {
  DataDeserialization() {
    this.getTarget().toString().matches("BinaryFormatter().Deserialize($stream)")
  }
}

from DataDeserialization
select DataDeserialization
```



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
using System;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;

public class DataDeserializer
{
    public object DeserializeData(byte[] data)
    {
        BinaryFormatter formatter = new BinaryFormatter();
        
        // Настройте пользовательский SerializationBinder, чтобы ограничить десериализацию доверенными типами
        formatter.Binder = new TrustedSerializationBinder();
        
        using (MemoryStream memoryStream = new MemoryStream(data))
        {
            try
            {
                // Десериализуем данные с надлежащей проверкой
                object deserializedData = formatter.Deserialize(memoryStream);
                
                // Выполните дополнительную проверку десериализованного объекта, если требуется
                
                return deserializedData;
            }
            catch (SerializationException ex)
            {
                Console.WriteLine("Error occurred during deserialization: " + ex.Message);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Unexpected error occurred: " + ex.Message);
            }
        }
        
        return null;
    }
}

// Пользовательский SerializationBinder для ограничения десериализации доверенными типами
public class TrustedSerializationBinder : SerializationBinder
{
    public override Type BindToType(string assemblyName, string typeName)
    {
        // Проверяем, является ли запрашиваемый тип доверенным
        if (IsTypeTrusted(typeName))
        {
            // Возвращаем доверенный тип для десериализации
            Type trustedType = GetTypeFromTrustedAssembly(typeName);
            return trustedType;
        }
        
        // Для недоверенных типов выбросьте исключение или верните null, чтобы предотвратить десериализацию
        throw new SerializationException("Attempted deserialization of untrusted type: " + typeName);
    }
    
    private bool IsTypeTrusted(string typeName)
    {
        // Реализуйте свою логику для определения того, является ли тип доверенным.
        // Например, ведение белого списка доверенных типов
        
        // Возвращаем true, если тип является доверенным, false в противном случае
        // ...
    }
    
    private Type GetTypeFromTrustedAssembly(string typeName)
    {
        // Получение доверенного типа из известной и доверенной сборки.
        // Например, ищем тип в предопределенной сборке.
        
        // Возвращаем объект Type для доверенного типа
        // ...
    }
}
```


В соответствующем коде было предпринято несколько мер для обеспечения безопасной десериализации данных. Во-первых, реализован пользовательский SerializationBinder для ограничения десериализации доверенными типами. Метод BindToType в классе TrustedSerializationBinder вызывается во время десериализации и проверяет, является ли запрашиваемый тип доверенным. Если тип является доверенным, он возвращает соответствующий объект Type для десериализации. В противном случае он выбрасывает SerializationException, чтобы предотвратить десериализацию недоверенных типов.



Кроме того, реализована обработка исключений, чтобы отлавливать возможные ошибки во время десериализации и выдавать соответствующие сообщения об ошибках.




Semgrep:


```
rules:
  - id: secure-data-deserialization
    pattern: BinaryFormatter().{ Deserialize($stream), Deserialize($stream, out _) }
    message: "Ensure secure data deserialization"
```

CodeQL:



```
import csharp

class DataDeserialization extends MethodCall {
  DataDeserialization() {
    this.getTarget().toString().matches("BinaryFormatter().{ Deserialize($stream), Deserialize($stream, out _) }")
  }
}

class DeserializationExceptionHandling extends TryStatement {
  DeserializationExceptionHandling() {
    getBody() instanceof Block and
    getBody().getChildren().get(0) instanceof ThrowStatement and
    getBody().getChildren().get(1) instanceof CatchClause
  }
}

from DataDeserialization d, DeserializationExceptionHandling e
where d.getAncestor(Statement+) = e.getAncestor(Statement+)
select d, e
```





## Недостаточное ведение журнала

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
using System;

public class PaymentProcessor
{
    public void ProcessPayment(double amount, string creditCardNumber)
    {
        // Обработка логики платежей
        
        try
        {
            // Выполните обработку платежа
            
            // Выведите сообщение об успехе
            Console.WriteLine("Платеж успешно обработан.");
        }
        catch (Exception ex)
        {
            // Выведите в журнал только сообщение об исключении
            Console.WriteLine("Payment processing failed. Exception: " + ex.Message);
        }
    }
}
```

В этом несоответствующем коде метод ProcessPayment выполняет обработку платежей, но не имеет достаточной регистрации. В коде регистрируется только сообщение об исключении при возникновении ошибки во время обработки платежа, что дает ограниченную информацию для поиска и устранения неисправностей.


Чтобы решить эту проблему и улучшить протоколирование, вот пример кода, соответствующего требованиям:








<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
using System;
using System.IO;

public class PaymentProcessor
{
    private readonly ILogger logger;

    public PaymentProcessor(ILogger logger)
    {
        this.logger = logger;
    }

    public void ProcessPayment(double amount, string creditCardNumber)
    {
        try
        {
            // Выполните обработку платежа

            // Выведите сообщение об успехе с подробной информацией
            string logMessage = $"Payment processed successfully. Amount: {amount}, Credit Card: {MaskCreditCardNumber(creditCardNumber)}";
            logger.LogInfo(logMessage);
        }
        catch (Exception ex)
        {
            // Занесите исключение в журнал с подробной информацией
            string errorMessage = $"Payment processing failed. Amount: {amount}, Credit Card: {MaskCreditCardNumber(creditCardNumber)}, Exception: {ex}";
            logger.LogError(errorMessage);
        }
    }

    private string MaskCreditCardNumber(string creditCardNumber)
    {
        // Реализуйте логику для маскировки конфиденциальной информации
        // Например, заменить все цифры, кроме последних четырех, на звездочки
        int maskLength = creditCardNumber.Length - 4;
        string maskedNumber = new string('*', maskLength) + creditCardNumber.Substring(maskLength);
        return maskedNumber;
    }
}

public interface ILogger
{
    void LogInfo(string message);
    void LogError(string message);
}
```


В соответствующем коде появился отдельный интерфейс ILogger для работы с функциями протоколирования. Класс PaymentProcessor теперь получает экземпляр ILogger через инъекцию зависимостей. Метод ProcessPayment записывает в журнал сообщение об успехе с подробной информацией об успешной обработке платежа. Оно включает сумму платежа и замаскированный номер кредитной карты, чтобы избежать записи конфиденциальной информации.


Если во время обработки платежа возникает исключение, код регистрирует сообщение об ошибке, включающее сумму платежа, замаскированный номер кредитной карты и подробности исключения. Это обеспечивает более полное протоколирование для устранения неполадок и проведения расследований.


Примечание: реализация интерфейса ILogger не приведена в данном фрагменте кода, поскольку она может зависеть от используемого в приложении фреймворка протоколирования или механизма хранения данных.




Semgrep:


```
rules:
  - id: secure-payment-processing
    pattern: |
      try {
        $processPaymentExpr
      } catch (Exception $ex) {
        Console.WriteLine("Payment processing failed. Exception: " + $ex.Message);
      }
    message: "Ensure secure payment processing"
```

CodeQL:



```
import csharp

class PaymentProcessing extends TryStatement {
  PaymentProcessing() {
    getBody() instanceof Block and
    getBody().getChildren().get(0) instanceof ExpressionStatement and
    getBody().getChildren().get(0).getChildren().get(0).toString().matches("$processPaymentExpr")
  }
}

from PaymentProcessing p
select p
```




## Неправильная нейтрализация выхода для бревен

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
using System;

public class LoginController
{
    private readonly ILogger logger;

    public LoginController(ILogger logger)
    {
        this.logger = logger;
    }

    public void LogUserLogin(string username)
    {
        // Введите логин пользователя
        logger.LogInfo("User login: " + username);
    }
}
```

В этом коде, не соответствующем требованиям, метод LogUserLogin регистрирует вход пользователя в систему путем конкатенации имени пользователя непосредственно в сообщении журнала. Это может привести к уязвимости инъекции в журнал, если имя пользователя содержит специальные символы, которые могут изменить формат или содержимое журнала.


Чтобы решить эту проблему и обеспечить надлежащую нейтрализацию вывода, вот пример совместимого кода:







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
using System;

public class LoginController
{
    private readonly ILogger logger;

    public LoginController(ILogger logger)
    {
        this.logger = logger;
    }

    public void LogUserLogin(string username)
    {
        // Зафиксируйте вход пользователя в систему с нейтрализованным выходом
        string logMessage = $"User login: {NeutralizeLogOutput(username)}";
        logger.LogInfo(logMessage);
    }

    private string NeutralizeLogOutput(string input)
    {
        // Реализуйте логику для нейтрализации специальных или управляющих символов в журнале.
        // Например, заменять новые строки, возвраты каретки или другие потенциально опасные символы
        string neutralizedOutput = input.Replace("\r", "").Replace("\n", "");
        return neutralizedOutput;
    }
}

public interface ILogger
{
    void LogInfo(string message);
}
```


В соответствующем коде метод LogUserLogin использует строковую интерполяцию для построения сообщения журнала, обеспечивая надлежащую нейтрализацию вывода. Метод NeutralizeLogOutput используется для нейтрализации любых специальных символов или управляющих символов, которые могут представлять угрозу безопасности при включении в вывод журнала. В этом примере перед записью в журнал из имени пользователя удаляются новые строки и возвраты каретки.

Нейтрализуя вывод журнала, соответствующий код снижает риск уязвимостей, связанных с инъекциями в журнал, и гарантирует, что сообщения журнала точно отражают предполагаемое содержимое без каких-либо непредвиденных последствий для системы регистрации.





Semgrep:


```
rules:
  - id: improper-output-neutralization
    pattern: |
      using System;
      
      public class LoginController
      {
          private readonly ILogger logger;
      
          public LoginController(ILogger logger)
          {
              this.logger = logger;
          }
      
          public void LogUserLogin(string username)
          {
              // Введите логин пользователя
              logger.LogInfo("User login: " + $username);
          }
      }
```

CodeQL:



```
import csharp

from MethodAccess ma, MethodAccess ma2, StringConcatenation concat
where
  ma.getTarget().getType().getQualifiedName() = "ILogger" and
  ma.getTarget().hasQualifiedName("ILogger", "LogInfo") and
  ma2.getTarget().getType().getQualifiedName() = "LoginController" and
  ma2.getTarget().getName() = "LogUserLogin" and
  concat.getAnOperand() = ma2.getTarget() and
  concat.getParent*().getAPrimaryQlClass() instanceof ExpressionStatement
select ma2, "Improper output neutralization for logs"
```




## Упущение информации, имеющей отношение к безопасности

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
using System;

public class PaymentController
{
    private readonly ILogger logger;

    public PaymentController(ILogger logger)
    {
        this.logger = logger;
    }

    public void ProcessPayment(decimal amount)
    {
        // Логика обработки платежей
        try
        {
            // Код обработки платежа здесь...

            logger.LogInfo("Payment processed successfully");
        }
        catch (Exception ex)
        {
            logger.LogError("Payment processing failed");
        }
    }
}

public interface ILogger
{
    void LogInfo(string message);
    void LogError(string message);
}
```


В этом несоответствующем коде интерфейс логгера (ILogger) используется для регистрации информационных сообщений и сообщений об ошибках во время обработки платежа. Однако код не включает в сообщения журнала никакой информации, связанной с безопасностью. Он предоставляет только общие сообщения без каких-либо конкретных деталей, которые могли бы помочь выявить или диагностировать потенциальные проблемы безопасности.


Чтобы решить эту проблему, приведем пример совместимого кода, который включает в сообщения журнала информацию, относящуюся к безопасности:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
using System;

public class PaymentController
{
    private readonly ILogger logger;

    public PaymentController(ILogger logger)
    {
        this.logger = logger;
    }

    public void ProcessPayment(decimal amount)
    {
        // Логика обработки платежей
        try
        {
            // Код обработки платежа здесь...

            logger.LogInfo($"Payment processed successfully. Amount: {amount}");
        }
        catch (Exception ex)
        {
            logger.LogError($"Payment processing failed. Amount: {amount}. Error: {ex.Message}");
        }
    }
}

public interface ILogger
{
    void LogInfo(string message);
    void LogError(string message);
}
```


В соответствующем коде сообщения журнала содержат конфиденциальную информацию, такую как сумма платежа, в дополнение к общему сообщению. Это обеспечивает больший контекст и помогает в аудите, устранении неполадок и обнаружении любых потенциальных инцидентов безопасности.






Semgrep:


```
rules:
  - id: improper-output-neutralization
    pattern: |
      using System;
      
      public class PaymentController
      {
          private readonly ILogger logger;
      
          public PaymentController(ILogger logger)
          {
              this.logger = logger;
          }
      
          public void ProcessPayment(decimal amount)
          {
              // Логика обработки платежей
              try
              {
                  // Код обработки платежа здесь...
      
                  logger.LogInfo($"Payment processed successfully: {amount}");
              }
              catch (Exception ex)
              {
                  logger.LogError("Payment processing failed");
              }
          }
      }
```

CodeQL:



```
import csharp

from MethodAccess ma, MethodAccess ma2, StringConcatenation concat
where
  ma.getTarget().getType().getQualifiedName() = "ILogger" and
  ma.getTarget().hasQualifiedName("ILogger", "LogInfo") and
  ma2.getTarget().getType().getQualifiedName() = "PaymentController" and
  ma2.getTarget().getName() = "ProcessPayment" and
  concat.getAnOperand() = ma2.getTarget() and
  concat.getParent*().getAPrimaryQlClass() instanceof ExpressionStatement
select ma2, "Improper output neutralization for logs"
```






## Sensitive Information into Log File

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
using System;
using System.IO;

public class UserController
{
    private readonly ILogger logger;

    public UserController(ILogger logger)
    {
        this.logger = logger;
    }

    public void CreateUser(string username, string password)
    {
        try
        {
            // Логика создания пользователя здесь...

            logger.LogInfo($"User '{username}' created successfully");
        }
        catch (Exception ex)
        {
            logger.LogError($"Failed to create user '{username}'");
        }
    }
}

public interface ILogger
{
    void LogInfo(string message);
    void LogError(string message);
}
```

В этом несоответствующем коде класс UserController включает метод CreateUser, который записывает конфиденциальную информацию, а именно имя пользователя и пароль, в файл журнала. Хранение такой конфиденциальной информации открытым текстом в файле журнала является уязвимостью безопасности, так как может привести к несанкционированному доступу в случае компрометации файлов журнала.


Чтобы решить эту проблему, ниже приведен пример соответствующего кода, который позволяет избежать записи конфиденциальной информации в файл журнала:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
using System;
using System.IO;

public class UserController
{
    private readonly ILogger logger;

    public UserController(ILogger logger)
    {
        this.logger = logger;
    }

    public void CreateUser(string username)
    {
        try
        {
            // Логика создания пользователя здесь...

            logger.LogInfo($"User '{username}' created successfully");
        }
        catch (Exception ex)
        {
            logger.LogError($"Failed to create user '{username}'");
        }
    }
}

public interface ILogger
{
    void LogInfo(string message);
    void LogError(string message);
}
```


В соответствующем коде метод CreateUser больше не принимает пароль в качестве параметра, поэтому он не записывается в файл журнала. Только имя пользователя, которое считается нечувствительной информацией, записывается в журнал для целей аудита и устранения неполадок. Очень важно избегать записи в журнал конфиденциальной информации, чтобы свести к минимуму риск утечки данных и несанкционированного доступа.




Semgrep:


```
rules:
  - id: improper-output-neutralization
    pattern: |
      using System;
      using System.IO;

      public class UserController
      {
          private readonly ILogger logger;

          public UserController(ILogger logger)
          {
              this.logger = logger;
          }

          public void CreateUser(string username, string password)
          {
              try
              {
                  // Логика создания пользователя здесь...

                  logger.LogInfo($"User '{username}' created successfully");
              }
              catch (Exception ex)
              {
                  logger.LogError($"Failed to create user '{username}'");
              }
          }
      }
```

CodeQL:



```
import csharp

from MethodAccess ma, MethodAccess ma2, StringConcatenation concat
where
  ma.getTarget().getType().getQualifiedName() = "ILogger" and
  ma.getTarget().hasQualifiedName("ILogger", "LogInfo") and
  ma2.getTarget().getType().getQualifiedName() = "UserController" and
  ma2.getTarget().getName() = "CreateUser" and
  concat.getAnOperand() = ma2.getTarget() and
  concat.getParent*().getAPrimaryQlClass() instanceof ExpressionStatement
select ma2, "Improper output neutralization for logs"
```






## Подделка запросов со стороны сервера (SSRF)

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
using System;
using System.Net;

public class ImageController
{
    public void DisplayImage(string url)
    {
        WebClient client = new WebClient();
        byte[] imageData = client.DownloadData(url);

        // Отображение изображения на сайте
        // ...
    }
}
```

В этом несоответствующем коде метод DisplayImage принимает на вход URL и напрямую выполняет запрос к этому URL с помощью класса WebClient. Этот код подвержен атакам SSRF, поскольку позволяет злоумышленнику указывать произвольные URL-адреса, включая внутренние или ограниченные сетевые ресурсы. Злоумышленник может злоупотребить этой функциональностью для выполнения запросов к важным внутренним системам, получения конфиденциальной информации или выполнения действий от имени сервера.


Для устранения этой уязвимости приведен пример совместимого кода, который включает проверку ввода и реализует подход, основанный на белых списках, для ограничения URL-адресов, к которым можно получить доступ:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
using System;
using System.Net;

public class ImageController
{
    public void DisplayImage(string url)
    {
        if (!IsAllowedURL(url))
        {
            throw new ArgumentException("Invalid image URL");
        }

        WebClient client = new WebClient();
        byte[] imageData = client.DownloadData(url);

        // Отображение изображения на сайте
        // ...
    }

    private bool IsAllowedURL(string url)
    {
        // Реализуйте логику для проверки того, разрешен ли URL-адрес.
        // Пример: Проверка по белому списку доверенных доменов или шаблонов.
        // ...
    }
}
```

В коде, соответствующем требованиям, метод DisplayImage теперь включает проверку ввода, чтобы гарантировать доступ только к разрешенным URL. Метод IsAllowedURL выполняет необходимые проверки, такие как сравнение URL с белым списком доверенных доменов или шаблонов. Если URL не разрешен, возникает исключение, предотвращающее уязвимость SSRF.

Реализуя надлежащую проверку ввода и ограничивая доступ только к доверенным URL, соответствующий код снижает риск атак SSRF и помогает обеспечить выполнение запросов к легитимным и авторизованным ресурсам.




Semgrep:


```
metadata:
  difficulty: Easy

rules:
  - id: display-image-insecure
    message: "Insecure image display: Potential security vulnerability when displaying images from external sources."
    severity: warning
    languages:
      - csharp
    patterns:
      - pattern: "WebClient client = new WebClient();\nbyte\\[\\] imageData = client.DownloadData($url$);"
        capture:
          - variable: url
```

CodeQL:



```
import csharp

from MethodAccess ma
where ma.getMethod().getName() = "DownloadData" and ma.getQualifier().getType().getName() = "WebClient"
select ma
```
