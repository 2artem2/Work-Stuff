---
layout: default
title: Android
parent: Rules
---

# Android
{: .no_toc }

## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---




## Java



### Неправильное использование платформы

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```java
// Несоответствующий код
public class InsecureStorageActivity extends AppCompatActivity {
    private SharedPreferences preferences;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_insecure_storage);
        
        preferences = getSharedPreferences("my_prefs", MODE_WORLD_READABLE);
    }

    // Остальной код...
}
```

В этом несоответствующем коде объект SharedPreferences создается с режимом MODE_WORLD_READABLE, что позволяет любому другому приложению прочитать сохраненные настройки. Это нарушает принцип правильного использования платформы, поскольку конфиденциальные данные не должны храниться таким образом, чтобы к ним был возможен несанкционированный доступ.





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Код соответствия:


```java
// Соответствующий код
public class SecureStorageActivity extends AppCompatActivity {
    private SharedPreferences preferences;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_secure_storage);
        
        preferences = getSharedPreferences("my_prefs", MODE_PRIVATE);
    }

    // Остальной код...
}
```


В совместимом коде объект SharedPreferences создается с режимом MODE_PRIVATE, который гарантирует, что предпочтения доступны только самому приложению. Это соответствует принципу правильного использования платформы, обеспечивая безопасное хранение конфиденциальных данных и не допуская несанкционированного доступа.

Используя MODE_PRIVATE вместо MODE_WORLD_READABLE, код, соответствующий требованиям, гарантирует, что сохраненные предпочтения доступны только в рамках приложения, что снижает риск раскрытия конфиденциальной информации другим приложениям на устройстве.



Semgrep:

Для Semgrep можно использовать следующее правило, чтобы обнаружить небезопасное использование MODE_WORLD_READABLE в SharedPreferences:

```
rules:
  - id: insecure-sharedpreferences
    patterns:
      - pattern: "getSharedPreferences\\(\"\\w+\",\\s*MODE_WORLD_READABLE\\)"
    message: "Insecure use of MODE_WORLD_READABLE in SharedPreferences"
```

CodeQL:

Для CodeQL вы можете использовать следующий запрос, чтобы обнаружить небезопасное использование MODE_WORLD_READABLE в SharedPreferences:


```
import java
import android

from MethodInvocation m
where m.getMethod().getQualifiedName() = "android.content.Context.getSharedPreferences"
  and m.getArgument(1).toString() = "MODE_WORLD_READABLE"
select m
```



### Insecure Data Storage

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```java
// Несоответствующий код
public class InsecureStorageActivity extends AppCompatActivity {
    private static final String FILENAME = "my_sensitive_data.txt";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_insecure_storage);
        
        String sensitiveData = "Это мои конфиденциальные данные".;
        writeToFile(sensitiveData);
    }

    private void writeToFile(String data) {
        try {
            File file = new File(getFilesDir(), FILENAME);
            FileWriter writer = new FileWriter(file);
            writer.write(data);
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Остальной код...
}
```

В этом несоответствующем коде конфиденциальные данные записываются в файл с помощью FileWriter без учета вариантов безопасного хранения. Данные хранятся в личном каталоге файлов приложения, но они не имеют надлежащего шифрования или дополнительных мер безопасности, что делает их уязвимыми для несанкционированного доступа.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Код соответствия:


```java
// Соответствующий код
public class SecureStorageActivity extends AppCompatActivity {
    private static final String FILENAME = "my_sensitive_data.txt";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_secure_storage);
        
        String sensitiveData = "Это мои конфиденциальные данные";
        writeToFile(sensitiveData);
    }

    private void writeToFile(String data) {
        try {
            FileOutputStream fos = openFileOutput(FILENAME, Context.MODE_PRIVATE);
            OutputStreamWriter writer = new OutputStreamWriter(fos);
            writer.write(data);
            writer.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // Остальной код...
}
```


В коде, соответствующем требованиям, FileOutputStream и OutputStreamWriter используются вместе с методом openFileOutput для безопасной записи конфиденциальных данных в файл в частном каталоге хранения приложения. Флаг MODE_PRIVATE гарантирует, что файл будет доступен только самому приложению. Это соответствует правилам безопасного хранения и помогает защитить конфиденциальные данные от несанкционированного доступа.

Используя openFileOutput с MODE_PRIVATE вместо FileWriter, код, соответствующий требованиям, обеспечивает безопасное хранение конфиденциальных данных, снижая риск несанкционированного доступа или раскрытия.



Semgrep:


```
rules:
  - id: insecure-file-write
    patterns:
      - pattern: "FileWriter\\.write\\(\\w+\\)"
    message: "Insecure file write operation"
```

CodeQL:



```
import java
import android

from MethodInvocation m
where m.getMethod().getQualifiedName() = "java.io.FileWriter.write"
select m
```


### Небезопасная связь

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```java
// Несоответствующий код
public class InsecureCommunicationActivity extends AppCompatActivity {
    private static final String API_URL = "http://example.com/api/";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_insecure_communication);
        
        String requestData = "Some sensitive data";
        String response = sendRequest(requestData);
        // Обработайте ответ...
    }

    private String sendRequest(String data) {
        try {
            URL url = new URL(API_URL);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            
            OutputStreamWriter writer = new OutputStreamWriter(conn.getOutputStream());
            writer.write(data);
            writer.flush();
            
            int responseCode = conn.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }
                reader.close();
                return response.toString();
            } else {
                // Обработка ответа на ошибку...
            }
            
            conn.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return null;
    }

    // Остальной код...
}
```

В этом несоответствующем коде приложение отправляет конфиденциальные данные по незащищенному HTTP-соединению (http://example.com/api/) с помощью HttpURLConnection. Это подвергает данные риску перехвата, фальсификации и несанкционированного доступа.







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```java
// Соответствующий код

public class SecureCommunicationActivity extends AppCompatActivity {
    private static final String API_URL = "https://example.com/api/";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_secure_communication);
        
        String requestData = "Some sensitive data";
        String response = sendRequest(requestData);
        // Обработайте ответ...
    }

    private String sendRequest(String data) {
        try {
            URL url = new URL(API_URL);
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            
            OutputStreamWriter writer = new OutputStreamWriter(conn.getOutputStream());
            writer.write(data);
            writer.flush();
            
            int responseCode = conn.getResponseCode();
            if (responseCode == HttpsURLConnection.HTTP_OK) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }
                reader.close();
                return response.toString();
            } else {
                // Обработка ответа на ошибку...
            }
            
            conn.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        return null;
    }

    // Остальной код...
}
```


В коде, соответствующем требованиям, приложение использует HttpsURLConnection для создания защищенного HTTPS-соединения (https://example.com/api/) для передачи конфиденциальных данных. HTTPS гарантирует, что связь зашифрована, обеспечивая конфиденциальность и целостность данных. Используя HTTPS вместо HTTP, совместимый код устраняет уязвимость небезопасной связи и снижает риск перехвата или несанкционированного доступа к конфиденциальным данным.



Semgrep:


```
rules:
  - id: insecure-file-write
    patterns:
      - pattern: "FileWriter\\.write\\(\\w+\\)"
    message: "Insecure file write operation"
```

CodeQL:



```
import java
import android

from MethodInvocation m
where m.getMethod().getQualifiedName() = "java.io.FileWriter.write"
select m
```


### Небезопасная аутентификация

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```java
// Несоответствующий код
public class LoginActivity extends AppCompatActivity {
    private EditText usernameEditText;
    private EditText passwordEditText;
    private Button loginButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);

        usernameEditText = findViewById(R.id.usernameEditText);
        passwordEditText = findViewById(R.id.passwordEditText);
        loginButton = findViewById(R.id.loginButton);

        loginButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String username = usernameEditText.getText().toString();
                String password = passwordEditText.getText().toString();

                if (username.equals("admin") && password.equals("admin123")) {
                    // Вход в систему успешный
                    openMainActivity();
                } else {
                    // Вход в систему не удался
                    Toast.makeText(LoginActivity.this, "Invalid username or password", Toast.LENGTH_SHORT).show();
                }
            }
        });
    }

    private void openMainActivity() {
        // Начните основную работу
        Intent intent = new Intent(this, MainActivity.class);
        startActivity(intent);
        finish();
    }
    
    // Остальная часть кода...
}
```

В этом несоответствующем коде приложение выполняет аутентификацию, сравнивая введенные пользователем имя пользователя и пароль (admin и admin123) с жестко закодированными значениями. Такой подход небезопасен, поскольку учетные данные легко обнаруживаются и могут быть использованы злоумышленниками.








<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Код соответствия:


```java
// Соответствующий код
public class LoginActivity extends AppCompatActivity {
    private EditText usernameEditText;
    private EditText passwordEditText;
    private Button loginButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_login);

        usernameEditText = findViewById(R.id.usernameEditText);
        passwordEditText = findViewById(R.id.passwordEditText);
        loginButton = findViewById(R.id.loginButton);

        loginButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String username = usernameEditText.getText().toString();
                String password = passwordEditText.getText().toString();

                // Выполняем безопасную аутентификацию
                if (authenticateUser(username, password)) {
                    // Вход в систему успешный
                    openMainActivity();
                } else {
                    // Вход не удался
                    Toast.makeText(LoginActivity.this, "Invalid username or password", Toast.LENGTH_SHORT).show();
                }
            }
        });
    }

    private boolean authenticateUser(String username, String password) {
        // Реализуйте здесь логику безопасной аутентификации
        // Пример: Выполнить безопасный вызов API для проверки учетных данных пользователя.
        // Возвращаем true в случае успешной аутентификации, false - в противном случае

        return false;
    }

    private void openMainActivity() {
        // Запуск основной активности
        Intent intent = new Intent(this, MainActivity.class);
        startActivity(intent);
        finish();
    }
    
    // Остальной код...
}
```


В коде, соответствующем требованиям, приложение выделяет логику аутентификации в специальный метод authenticateUser(), который может быть реализован безопасно. Этот метод может использовать такие механизмы безопасной аутентификации, как хеширование, солевая обработка и проверка на стороне сервера. Реализуя безопасный процесс аутентификации вместо того, чтобы полагаться на жестко заданные учетные данные, код, соответствующий требованиям, устраняет уязвимость небезопасной аутентификации и снижает риск несанкционированного доступа к учетным записям пользователей.


Semgrep:


```
rules:
  - id: insecure-login-credentials
    patterns:
      - pattern: '(username.equals\\("admin"\\) && password.equals\\("admin123"\\))'
    message: "Insecure use of hardcoded login credentials"
```

CodeQL:



```
import java
import android

from BinaryExpression b
where b.getLeftOperand().toString() = "username.equals(\"admin\")"
  and b.getRightOperand().toString() = "password.equals(\"admin123\")"
select b
```




### Недостаточная криптография

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```java
// Несоответствующий код
public class EncryptionUtils {
    private static final String KEY = "mySecretKey";
    
    public static String encrypt(String data) {
        try {
            Key key = generateKey();
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encryptedData = cipher.doFinal(data.getBytes());
            return Base64.encodeToString(encryptedData, Base64.DEFAULT);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    
    public static String decrypt(String encryptedData) {
        try {
            Key key = generateKey();
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decodedData = Base64.decode(encryptedData, Base64.DEFAULT);
            byte[] decryptedData = cipher.doFinal(decodedData);
            return new String(decryptedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    
    private static Key generateKey() throws Exception {
        return new SecretKeySpec(KEY.getBytes(), "AES");
    }
    
    // Остальной код...
}
```

В этом несоответствующем коде реализован пользовательский класс EncryptionUtils для шифрования и расшифровки данных с помощью алгоритма AES. Однако код использует жестко закодированный ключ (mySecretKey) и не включает другие важные меры безопасности, такие как выделение, усиление ключа или безопасное хранение ключей. Такой подход недостаточен и может быть уязвим для различных криптографических атак.







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Код соответствия:


```java
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import android.util.Base64;

public class EncryptionUtils {
    private static final String KEY_ALGORITHM = "AES";
    private static final String CIPHER_TRANSFORMATION = "AES/CBC/PKCS7Padding";

    private SecretKeySpec secretKeySpec;
    private IvParameterSpec ivParameterSpec;

    public EncryptionUtils(String secretKey) {
        try {
            byte[] keyBytes = generateKeyBytes(secretKey);
            secretKeySpec = new SecretKeySpec(keyBytes, KEY_ALGORITHM);
            ivParameterSpec = new IvParameterSpec(keyBytes);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String encrypt(String data) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] encryptedData = cipher.doFinal(data.getBytes());
            return Base64.encodeToString(encryptedData, Base64.DEFAULT);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public String decrypt(String encryptedData) {
        try {
            Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            byte[] decodedData = Base64.decode(encryptedData, Base64.DEFAULT);
            byte[] decryptedData = cipher.doFinal(decodedData);
            return new String(decryptedData);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private byte[] generateKeyBytes(String secretKey) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(secretKey.getBytes());
        return md.digest();
    }
}
```


В совместимом коде генерация ключа была улучшена за счет использования более безопасного подхода. Вместо простого преобразования байтов секретного ключа используется алгоритм хэширования (SHA-256) для получения более надежного ключа из секретного ключа. Это повышает безопасность процесса шифрования за счет использования более надежной функции получения ключа.



Semgrep:


```
rules:
  - id: insecure-encryption-key
    patterns:
      - pattern: "return new SecretKeySpec\\(KEY.getBytes\\(\\), \"AES\"\\)"
    message: "Insecure use of hard-coded encryption key"
```

CodeQL:



```
import java
import javax.crypto

from MethodInvocation m
where m.getMethod().getQualifiedName() = "javax.crypto.spec.SecretKeySpec.<init>"
  and m.getArgument(0).toString() = "KEY.getBytes()"
  and m.getArgument(1).toString() = "\"AES\""
select m
```


### Небезопасная авторизация

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```java
public class AuthorizationUtils {
    public boolean checkAdminAccess(String username, String password) {
        if (username.equals("admin") && password.equals("password")) {
            return true;
        } else {
            return false;
        }
    }
}
```

В этом несоответствующем коде метод checkAdminAccess выполняет небезопасную проверку авторизации, сравнивая имя пользователя и пароль непосредственно с жестко заданными значениями. Такой подход уязвим для таких атак, как угадывание пароля и брутфорс, а также для несанкционированного доступа, если учетные данные скомпрометированы.

Чтобы решить эту проблему, приведем пример совместимого кода для безопасной авторизации в Android Java:








<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```java
public class AuthorizationUtils {
    private static final String ADMIN_USERNAME = "admin";
    private static final String ADMIN_PASSWORD = "password";

    public boolean checkAdminAccess(String username, String password) {
        // Выполните логику безопасной аутентификации
        // Это может включать получение учетных данных пользователя из безопасного источника,
        // например, из базы данных, и сравнение их с помощью безопасного алгоритма хеширования.
        // В демонстрационных целях мы будем использовать простое сравнение с жестко заданными значениями.

        if (username.equals(ADMIN_USERNAME) && password.equals(ADMIN_PASSWORD)) {
            return true;
        } else {
            return false;
        }
    }
}
```


В соответствующем коде сравнение имени пользователя и пароля по-прежнему присутствует, но фактические учетные данные хранятся в защищенном виде, например, в защищенной базе данных или в формате хэширования и солерования. Кроме того, в этом коде приведен пример, в котором жестко заданные значения определены как константы, что упрощает управление и обновление учетных данных в случае необходимости. Для обеспечения безопасной авторизации в реальных сценариях важно применять надлежащие механизмы аутентификации, такие как использование безопасного хранения паролей и надежных протоколов аутентификации.


Semgrep:


```
rules:
  - id: insecure-admin-access
    patterns:
      - pattern: 'username.equals\\("admin"\\) && password.equals\\("password"\\)'
    message: "Insecure use of hardcoded admin credentials"
```

CodeQL:



```
import java

class AuthorizationUtils extends AnyFile
{
  AuthorizationUtils() {
    exists(
      MethodDeclaration m |
      m.getEnclosingType().toString() = "AuthorizationUtils" and
      m.getParameters().toString() = "[String username, String password]" and
      m.getReturnType().toString() = "boolean" and
      m.getBody().toString() = "if (username.equals(\"admin\") && password.equals(\"password\")) {\n            return true;\n        } else {\n            return false;\n        }"
    )
  }
}
```


### Качество клиентского кода

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```java
public class MainActivity extends AppCompatActivity {
    private TextView textView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        textView = findViewById(R.id.textView);

        // Выполните длинную и сложную операцию в главном потоке пользовательского интерфейса
        for (int i = 0; i < 1000000; i++) {
            // Выполните несколько тяжелых вычислений
        }

        // Обновление пользовательского интерфейса
        textView.setText("Операция завершена");
    }
}
```

В этом несоответствующем коде длинная и сложная операция выполняется непосредственно в главном потоке пользовательского интерфейса в методе onCreate класса MainActivity. Выполнение таких тяжелых вычислений в главном потоке пользовательского интерфейса может привести к тому, что приложение перестанет реагировать на запросы и негативно повлияет на работу пользователя. Чтобы пользовательский интерфейс оставался отзывчивым, необходимо перекладывать трудоемкие операции на фоновые потоки.


Чтобы решить эту проблему, приведем пример совместимого кода, который улучшает качество клиентского кода в Android Java:









<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```java
public class MainActivity extends AppCompatActivity {
    private TextView textView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        textView = findViewById(R.id.textView);

        // Выполняем длинную и сложную операцию в фоновом потоке
        new Thread(new Runnable() {
            @Override
            public void run() {
                for (int i = 0; i < 1000000; i++) {
                    // Выполните несколько тяжелых вычислений
                }

                // Обновление пользовательского интерфейса в главном потоке
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        // Обновление пользовательского интерфейса
                        textView.setText("Операция завершена");
                    }
                });
            }
        }).start();
    }
}
```


В совместимом коде тяжелые вычисления выполняются в фоновом потоке с использованием Thread или других механизмов параллелизма. После завершения вычислений обновление пользовательского интерфейса выполняется в основном потоке UI с помощью runOnUiThread для обеспечения надлежащей синхронизации с пользовательским интерфейсом. Перекладывая тяжелые вычисления на фоновый поток, пользовательский интерфейс остается отзывчивым, обеспечивая лучшее качество работы пользователя.


Semgrep:


```
rules:
  - id: long-operation-on-ui-thread
    patterns:
      - pattern: 'for \(int i = 0; i < \d+; i\+\+\)'
    message: "Long-running operation on the main UI thread"
```

CodeQL:



```
import android

class MainActivity extends AnyFile
{
  MainActivity() {
    exists(
      MethodDeclaration m |
      m.getEnclosingType().toString() = "MainActivity" and
      m.getQualifiedName() = "android.app.Activity.onCreate(Bundle)" and
      m.getBody().toString().indexOf("for (int i = 0; i < 1000000; i++)") >= 0
    )
  }
}
```


### Вскрытие кодов

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```java
public class MainActivity extends AppCompatActivity {
    private TextView textView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        textView = findViewById(R.id.textView);

        // Проверяем, установлено ли приложение из неавторизованного источника
        boolean isAuthorizedSource = checkInstallationSource();

        if (!isAuthorizedSource) {
            // Показываем сообщение об ошибке и выходим из приложения
            textView.setText("Установка неавторизованного приложения");
            finish();
        }

        // Остальная часть кода...
    }

    private boolean checkInstallationSource() {
        // Выполняем проверку для определения источника установки приложения
        // Для простоты предположим, что в этом примере проверка всегда возвращает false
        return false;
    }
}
```

В этом несоответствующем коде в методе onCreate выполняется проверка, не установлено ли приложение из неавторизованного источника. Если проверка не проходит (возвращается false), выводится сообщение об ошибке, но приложение продолжает выполняться.



Чтобы решить эту проблему, вот пример совместимого кода, который защищает от несанкционированного доступа к коду в Android Java:










<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```java
public class MainActivity extends AppCompatActivity {
    private TextView textView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        textView = findViewById(R.id.textView);

        // Проверяем, установлено ли приложение из неавторизованного источника
        boolean isAuthorizedSource = checkInstallationSource();

        if (!isAuthorizedSource) {
            // Показываем сообщение об ошибке и выходим из приложения
            textView.setText("Установка неавторизованного приложения");
            finishAffinity(); // Закрываем все действия и выходим из приложения
            return; // Предотвращение дальнейшего выполнения кода
        }

        // Остальная часть кода...
    }

    private boolean checkInstallationSource() {
        // Выполняем проверку для определения источника установки приложения
        // Для простоты предположим, что в этом примере проверка всегда возвращает false
        return false;
    }
}
```


В совместимом коде, когда проверка на несанкционированную установку приложения не проходит, вызывается метод finishAffinity(), чтобы закрыть все действия и выйти из приложения. Кроме того, оператор return используется для предотвращения дальнейшего выполнения кода в методе onCreate. Прекращение выполнения приложения при обнаружении источника несанкционированной установки снижает вероятность вмешательства в код.


Semgrep:


```
rules:
  - id: unauthorized-app-installation-check
    patterns:
      - pattern: 'checkInstallationSource\(\)'
    message: "Unauthorized app installation check"
```

CodeQL:



```
import android

class MainActivity extends AnyFile
{
  MainActivity() {
    exists(
      MethodDeclaration m |
      m.getEnclosingType().toString() = "MainActivity" and
      m.getQualifiedName() = "android.app.Activity.onCreate(Bundle)" and
      m.getBody().toString().indexOf("checkInstallationSource()") >= 0
    )
  }
}
```



### Обратное проектирование

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```java
public class MainActivity extends AppCompatActivity {
    private TextView textView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        textView = findViewById(R.id.textView);

        // Выполняем чувствительную операцию
        String sensitiveData = performSensitiveOperation();

        // Отображение чувствительных данных на экране
        textView.setText(sensitiveData);

        // Остальная часть кода...
    }

    private String performSensitiveOperation() {
        // Выполняем конфиденциальную операцию
        // Для простоты предположим, что она включает обработку конфиденциальных данных

        return "Sensitive Data";
    }
}
```

В этом несоответствующем коде конфиденциальные данные обрабатываются в методе performSensitiveOperation. Полученные конфиденциальные данные затем непосредственно отображаются на экране в методе onCreate, что облегчает злоумышленнику обратное проектирование и извлечение конфиденциальной информации из APK.




Чтобы решить эту проблему, вот пример совместимого кода, который защищает от обратного инжиниринга в Android Java:











<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```java
public class MainActivity extends AppCompatActivity {
    private TextView textView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        textView = findViewById(R.id.textView);

        // Выполняем чувствительную операцию
        String sensitiveData = performSensitiveOperation();

        // Выводим на экран общее сообщение
        textView.setText("Чувствительные данные защищены");

        // Остальная часть кода...
    }

    private String performSensitiveOperation() {
        // Выполняем чувствительную операцию
        // Для простоты предположим, что она связана с обработкой конфиденциальных данных

        return "Sensitive Data";
    }
}
```

В совместимом коде вместо прямого отображения конфиденциальных данных на экране показывается общее сообщение, чтобы избежать раскрытия конфиденциальной информации. Обфусцирование конфиденциальных данных и отображение общего сообщения усложняет попытки обратного инжиниринга, что затрудняет злоумышленникам извлечение конфиденциальной информации из APK.



Semgrep:


```
rules:
  - id: sensitive-data-display
    patterns:
      - pattern: 'textView.setText\(performSensitiveOperation\(\)\)'
    message: "Sensitive data display"
```

CodeQL:



```
import android

class MainActivity extends AnyFile
{
  MainActivity() {
    exists(
      MethodDeclaration m |
      m.getEnclosingType().toString() = "MainActivity" and
      m.getQualifiedName() = "android.app.Activity.onCreate(Bundle)" and
      m.getBody().toString().indexOf("textView.setText(performSensitiveOperation())") >= 0
    )
  }
}
```


### Extraneous Functionality

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```java
public class MainActivity extends AppCompatActivity {
    private Кнопка loginButton;
    private Кнопка adminButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        loginButton = findViewById(R.id.loginButton);
        adminButton = findViewById(R.id.adminButton);

        loginButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // Выполняем функцию входа в систему
                performLogin();
            }
        });

        adminButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // Выполнение функций администратора
                performAdminAction();
            }
        });

        // Остальной код...
    }

    private void performLogin() {
        // Функциональность входа в систему
    }

    private void performAdminAction() {
        // Функциональность администратора
    }
}
```

В этом несоответствующем коде есть кнопка adminButton и связанная с ней функциональность для выполнения административных действий. Однако если приложение не требует или не собирается предоставлять административную функциональность обычным пользователям, это может создать ненужный риск. Это увеличивает площадь атаки и потенциал несанкционированного доступа, если злоумышленник получит контроль над приложением.


Чтобы решить эту проблему, приведем пример совместимого кода, в котором удалена лишняя функциональность:




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```java
public class MainActivity extends AppCompatActivity {
    private Кнопка loginButton;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        loginButton = findViewById(R.id.loginButton);

        loginButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // Выполняем функцию входа в систему
                performLogin();
            }
        });

        // Остальной код...
    }

    private void performLogin() {
        // Функциональность входа в систему
    }
}
```


В коде, соответствующем требованиям, кнопка adminButton и связанная с ней административная функциональность были удалены. Теперь приложение сосредоточено исключительно на функциях входа в систему для обычных пользователей, что уменьшает площадь атаки и устраняет ненужную функциональность, которая может представлять потенциальные риски безопасности.



Semgrep:


```
rules:
  - id: hardcoded-actions
    patterns:
      - pattern: 'performLogin\(\)'
      - pattern: 'performAdminAction\(\)'
    message: "Hardcoded actions in onClick methods"
```

CodeQL:



```
import android

class MainActivity extends AnyFile
{
  MainActivity() {
    exists(
      MethodDeclaration m |
      m.getEnclosingType().toString() = "MainActivity" and
      m.getBody().getAStatement() instanceof MethodInvocation and
      (
        m.getBody().getAStatement().toString().indexOf("performLogin()") >= 0 or
        m.getBody().getAStatement().toString().indexOf("performAdminAction()") >= 0
      )
    )
  }
}
```
