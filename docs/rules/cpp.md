---
layout: default
title: Cpp
parent: Rules
---

# Cpp
{: .no_toc }



## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---





## Переполнение буфера


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```c
#include <iostream>

int main() {
    char buffer[5];
    strcpy(buffer, "Hello, world!"); // Несоответствующий код

    // Остальной код...
}
```

В коде, не соответствующем требованиям, объявляется буфер символьного массива размером 5. Затем используется функция strcpy для копирования строки в буфер. Однако для хранения строки "Hello, world!" требуется более 5 символов, что приводит к переполнению буфера. Запись за пределы буфера приводит к неопределенному поведению и потенциальным уязвимостям в системе безопасности.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```c
#include <iostream>
#include <cstring>

int main() {
    char buffer[20];
    strncpy(buffer, "Hello, world!", sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';

    // Остальной код...
}
```


Соответствующий код объявляет буфер символьного массива размером 20, что обеспечивает достаточное пространство для хранения строки. Для копирования строки в буфер используется функция strncpy, при этом количество копируемых символов ограничивается размером буфера минус 1. Кроме того, явно добавляется нулевой терминатор, чтобы обеспечить правильное завершение строки.





Semgrep:


```
rules:
- id: buffer-overflow
  pattern: strcpy($buffer, $source)
  message: Potential buffer overflow detected
```

CodeQL:



```
import cpp

from CallExpr strcpyCall
where strcpyCall.getArgument(0).getType().toString() = "char[]"
select strcpyCall,
       "Potential buffer overflow detected" as message
```






## Разыменование нулевого указателя


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```c
void foo(int* ptr) {
    if (ptr != nullptr) {
        *ptr = 42;
    } else {
        // ошибка обработки
    }
}

int main() {
    int* ptr = nullptr;
    foo(ptr);
    return 0;
}
```

В этом примере функция foo() принимает указатель на целое число и разыменовывает его, чтобы установить его значение в 42, но не проверяет, является ли указатель нулевым. Если в foo() будет передан нулевой указатель, произойдет разыменование нулевого указателя, что может привести к аварийному завершению программы или ее неопределенному поведению.





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```c
void foo(int* ptr) {
    if (ptr != nullptr) {
        *ptr = 42;
    } else {
        // ошибка обработки
    }
}

int main() {
    int i = 0;
    int* ptr = &i;
    foo(ptr);
    return 0;
}
```


В соответствующем коде указатель инициализируется на действительный адрес целочисленной переменной i с помощью оператора адреса &. Это гарантирует, что указатель не является нулевым, и предотвращает разыменование нулевого указателя.

В качестве альтернативы функция foo() может быть модифицирована для изящной обработки нулевых указателей, например, возвращать код ошибки или выбрасывать исключение. В целом, важно всегда проверять указатели на null перед их разыменованием, чтобы предотвратить разыменование нулевого указателя, которое может привести к сбоям и уязвимостям безопасности.





Semgrep:


```
rules:
  - id: null-pointer-dereference
    patterns:
      - pattern: 'if \(ptr != nullptr\)'
    message: "Potential null pointer dereference"
```

CodeQL:



```
import cpp

from Function f
where f.getName() = "foo"
select f
```






## Целочисленное переполнение/недополнение


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```c
#include <iostream>

int main() {
    int a = INT_MAX;
    int b = 1;
    int result = a + b;

    std::cout << "Result: " << result << std::endl;

    // Остальная часть кода...
}
```

В коде, не соответствующем требованиям, программа выполняет операцию сложения между a и b без проверки на потенциальное переполнение целого числа. Если значение a уже достигло своего максимума (INT_MAX), сложение приведет к неопределенному поведению из-за переполнения целого числа.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```c
#include <iostream>
#include <limits>

int main() {
    int a = INT_MAX;
    int b = 1;

    if (a > std::numeric_limits<int>::max() - b) {
        std::cout << "Integer overflow occurred!" << std::endl;
    } else {
        int result = a + b;
        std::cout << "Result: " << result << std::endl;
    }

    // Остальная часть кода...
}
```


Соответствующий код включает проверку на потенциальное целочисленное переполнение перед выполнением сложения. Он сравнивает значение `a` с максимальным значением целочисленного типа (`std::numeric_limits<int>::max()`) минус `b`. Если сравнение показывает, что произойдет переполнение, можно предпринять соответствующие действия для обработки условия переполнения. В данном примере при обнаружении переполнения выводится информационное сообщение.





Semgrep:


```
rules:
- id: integer-overflow
  pattern: |
    int a = INT_MAX;
    int b = 1;
    int result = a + b;
  message: Potential integer overflow/underflow detected
```

CodeQL:



```
import cpp

from Function main() {
  where exists(BinaryOperator addition | subtraction |
              multiplication | division |
              modulus | shift) and
              (addition.getOperandType() = int() or
              subtraction.getOperandType() = int() or
              multiplication.getOperandType() = int() or
              division.getOperandType() = int() or
              modulus.getOperandType() = int() or
              shift.getOperandType() = int())
  select addition, subtraction, multiplication, division, modulus, shift,
         "Potential integer overflow/underflow detected" as message
}
```




## Отказ в обслуживании (DoS)


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```c
#include <iostream>

void processRequest() {
    // Обработка запроса
    // ...

    // Преднамеренный бесконечный цикл
    while (true) {
        // Выполните какую-нибудь дорогостоящую операцию
        // ...
    }
}

int main() {
    processRequest();

    // Остальной код...
}
```

В коде, не соответствующем требованиям, функция processRequest содержит намеренный бесконечный цикл, выполняющий дорогостоящую операцию. Это может привести к DoS-уязвимости, поскольку потребляет чрезмерное количество ресурсов, например процессорного времени, что приводит к отказу приложения или системы от реагирования.








<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```c
#include <iostream>

void processRequest() {
    // Обработка запроса
    // ...
}

int main() {
    processRequest();

    // Остальной код...
}
```


Соответствующий код устраняет преднамеренный бесконечный цикл из функции processRequest, благодаря чему приложение не потребляет лишних ресурсов и остается отзывчивым. Устранив ресурсоемкую операцию, соответствующий код устраняет DoS-уязвимость.




Semgrep:


```

```

CodeQL:



```

```







## Format String


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:

```c
#include <iostream>

int main() {
    char* user_input = nullptr;
    std::cout << "Введите ваше имя: ";
    std::cin >> user_input;

    // Несоответствующий код
    printf(user_input);

    // Остальной код...
}
```

В коде, не соответствующем требованиям, пользовательский ввод напрямую передается в качестве аргумента строки формата в функцию printf. Если пользовательский ввод содержит спецификаторы формата, это может привести к уязвимости Format String. Злоумышленник может использовать эту уязвимость для чтения или модификации памяти, выполнения произвольного кода или аварийного завершения работы приложения.







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```c
#include <iostream>

int main() {
    char user_input[256];
    std::cout << "Введите ваше имя: ";
    std::cin >> user_input;

    // Соответствующий код
    std::cout << user_input << std::endl;

    // Остальной код...
}
```


Соответствующий код использует поток std::cout для печати пользовательского ввода, что позволяет избежать прямого использования уязвимости форматной строки. Благодаря использованию std::cout вводимые данные обрабатываются как обычная строка и не интерпретируются как строка форматирования.



Semgrep:


```
rules:
- id: format-string-vulnerability
  pattern: printf($format)
  message: Potential format string vulnerability detected
```

CodeQL:



```
import cpp

from FunctionCall printfCall
where printfCall.getTarget().hasName("printf") and
      printfCall.getArgument(0).getType().toString() = "char*"
select printfCall,
       "Potential format string vulnerability detected" as message
```




## Ненадежная криптография


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:

```c
#include <iostream>
#include <openssl/md5.h

std::string generateHash(const std::string& data) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((unsigned char*)data.c_str(), data.length(), digest);

    char hexDigest[MD5_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        sprintf(hexDigest + (i * 2), "%02x", digest[i]);
    }

    return std::string(hexDigest);
}

int main() {
    std::string password = "myPassword";
    std::string hashedPassword = generateHash(password);

    std::cout << "Hashed Password: " << hashedPassword << std::endl;

    // Остальная часть кода...
}
```

В коде, не соответствующем требованиям, для генерации хэша пароля используется алгоритм хэширования MD5. Однако MD5 считается небезопасным для криптографических целей из-за его уязвимости к атакам на столкновения и наличия более быстрых и безопасных алгоритмов хэширования. Использование MD5 для хэширования паролей может подвергнуть приложение рискам безопасности.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```c
#include <iostream>
#include <openssl/sha.h

std::string generateHash(const std::string& data) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)data.c_str(), data.length(), digest);

    char hexDigest[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        sprintf(hexDigest + (i * 2), "%02x", digest[i]);
    }

    return std::string(hexDigest);
}

int main() {
    std::string password = "myPassword";
    std::string hashedPassword = generateHash(password);

    std::cout << "Hashed Password: " << hashedPassword << std::endl;

    // Остальная часть кода...
}
```


Соответствующий код решает проблему небезопасной криптографии, заменяя MD5 на более безопасный алгоритм хэширования SHA-256. SHA-256 считается более сильным и устойчивым к атакам на столкновения.



Semgrep:


```
rules:
- id: insecure-cryptography
  pattern: MD5($data)
  message: Insecure cryptography algorithm (MD5) detected
```

CodeQL:



```
import cpp

from FunctionCall md5Call
where md5Call.getTarget().hasQualifiedName("MD5")
select md5Call,
       "Insecure cryptography algorithm (MD5) detected" as message
```






## Повреждение памяти


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```c
#include <iostream>

void writeToMemory(char* buffer, const char* data, size_t length) {
    strcpy(buffer, data); // Несоответствующий код
    buffer[length] = '\0'; // Несоответствующий код
}

int main() {
    char buffer[10];
    const char* data = "Hello, World!";

    writeToMemory(buffer, data, strlen(data));

    std::cout << "Буфер: " << buffer << std::endl;

    // Остальной код...
}
```

В коде, не соответствующем требованиям, функция writeToMemory использует функцию strcpy для копирования данных в буфер без надлежащей проверки границ. Это может привести к переполнению буфера, что приведет к повреждению памяти. Кроме того, код пытается записать нулевой терминатор за пределами размера буфера, что приводит к перечитыванию буфера и потенциальному повреждению памяти.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```c
#include <iostream>
#include <cstring>

void writeToMemory(char* buffer, const char* data, size_t length) {
    strncpy(buffer, data, length);
    buffer[length - 1] = '\0';
}

int main() {
    char buffer[10];
    const char* data = "Hello, World!";

    writeToMemory(buffer, data, sizeof(buffer));

    std::cout << "Buffer: " << buffer << std::endl;

    // Остальная часть кода...
}
```


Соответствующий код решает проблему повреждения памяти, используя strncpy вместо strcpy для копирования данных в буфер, что обеспечивает соблюдение длины. Код также корректно устанавливает нулевой терминатор в пределах ограничения размера буфера.


Semgrep:


```
rules:
- id: memory-corruption
  pattern: strcpy($buffer, $data)
  message: Potential memory corruption (strcpy) detected
```

CodeQL:



```
import cpp

from FunctionCall strcpyCall
where strcpyCall.getTarget().hasName("strcpy")
select strcpyCall,
       "Potential memory corruption (strcpy) detected" as message
```





## Инъекция кода


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```c
#include <iostream>

void executeCommand(const std::string& command) {
    std::string fullCommand = "echo " + command;
    system(fullCommand.c_str()); // Несоответствующий код
}

int main() {
    std::string userInput;
    std::cout << "Введите команду: ";
    std::cin >> userInput;

    executeCommand(userInput);

    // Остальной код...
}
```

В коде, не соответствующем требованиям, функция executeCommand формирует команду путем конкатенации пользовательского ввода с фиксированной строкой и затем передает ее системной функции. Это может привести к уязвимости Code Injection, поскольку злоумышленник может манипулировать пользовательским вводом для выполнения произвольных команд в системе.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```c
#include <iostream>

void executeCommand(const std::string& command) {
    std::cout << "Выполнение команды: " << command << std::endl;
    // Выполнение команды безопасным методом
    // ...
}

int main() {
    std::string userInput;
    std::cout << "Введите команду: ";
    std::cin >> userInput;

    executeCommand(userInput);

    // Остальной код...
}
```


Соответствующий код устраняет уязвимость Code Injection, не создавая командную строку с помощью пользовательского ввода и не выполняя ее с помощью системной функции. Вместо этого он использует безопасный метод для выполнения команды, который может включать строгую проверку ввода, использование авторизованной библиотеки выполнения команд или использование системных API с надлежащими мерами защиты.


Semgrep:


```
rules:
- id: code-injection
  pattern: system($command)
  message: Potential code injection vulnerability detected
```

CodeQL:



```
import cpp

from FunctionCall systemCall
where systemCall.getTarget().hasName("system")
select systemCall,
       "Potential code injection vulnerability detected" as message
```




## Перехват DLL


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:

```c
#include <iostream>
#include <windows.h>

int main() {
    HMODULE hModule = LoadLibrary("evil.dll"); // Несоответствующий код
    if (hModule != NULL) {
        // DLL успешно загружена, переходим к ее использованию
        // ...
    }

    // Остальной код...
}
```

В коде, не соответствующем требованиям, функция LoadLibrary используется для загрузки DLL с именем "evil.dll" без указания полного пути. Это может привести к уязвимости DLL Hijacking, так как злоумышленник может поместить вредоносную DLL с таким же именем в место, где приложение ищет DLL, что приведет к выполнению неавторизованного кода.


<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```c
#include <iostream>
#include <windows.h>

int main() {
    std::string dllPath = "C:\\path\\to\\safe.dll";
    HMODULE hModule = LoadLibrary(dllPath.c_str());
    if (hModule != NULL) {
        // DLL успешно загружена, переходим к ее использованию
        // ...
    }

    // Остальной код...
}
```


Соответствующий код устраняет уязвимость DLL Hijacking, указывая полный путь к загружаемой DLL с помощью функции LoadLibrary. Указывая полный путь, приложение обеспечивает загрузку нужной DLL и предотвращает возможность загрузки вредоносной DLL из неавторизованного места.



Semgrep:


```
rules:
- id: dll-hijacking
  pattern: LoadLibrary($dllName)
  message: Potential DLL Hijacking vulnerability detected
```

CodeQL:



```
import cpp

from FunctionCall loadLibraryCall
where loadLibraryCall.getTarget().hasName("LoadLibrary")
select loadLibraryCall,
       "Potential DLL Hijacking vulnerability detected" as message
```





## Use After Free


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:

```c
#include <iostream>

int* createObject() {
    return new int(5);
}

int main() {
    int* ptr = createObject();
    удалить ptr;
    std::cout << "Значение: " << *ptr << std::endl; // Несоответствующий код

    // Остальной код...
}
```

В коде, не соответствующем требованиям, объект динамически выделяется с помощью new и присваивается указателю ptr. Позже вызывается delete для деаллокации объекта, в результате чего указатель ptr становится висячим указателем. Несоответствующий код пытается разыменовать висящий указатель, обращаясь к освобожденной памяти, что приводит к Use After Free, поскольку память больше не действительна.


<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:

```c
#include <iostream>

int* createObject() {
    return new int(5);
}

int main() {
    int* ptr = createObject();
    std::cout << "Значение: " << *ptr << std::endl;

    delete ptr; // Деаллокация памяти

    // Остальная часть кода...
}
```


Соответствующий код гарантирует, что указатель ptr будет разыменован до того, как будет деаллоцирована связанная с ним память. После печати значения память освобождается с помощью delete, что предотвращает уязвимости Use After Free.


Semgrep:


```
rules:
- id: use-after-free
  pattern: "$expr"
  message: Potential use after free detected
```

CodeQL:



```
import cpp

from DestructorCall destructor
where exists(destructor.getDestructorMethod().getQualifiedName())
select destructor,
       "Potential use after free detected" as message
```






## Неинициализированные переменные


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```c
#include <iostream>

int main() {
    int value;
    std::cout << "Значение: " << value << std::endl; // Несоответствующий код

    // Остальной код...
}
```

В коде, не соответствующем требованиям, переменная value объявлена, но не инициализирована. Затем она используется в операторе std::cout без присвоения ей значения. Это приводит к чтению неинициализированной памяти, что приводит к неопределенному поведению и потенциальным уязвимостям безопасности.


<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```c
#include <iostream>

int main() {
    int value = 0; // Инициализация переменной
    std::cout << "Значение: " << value << std::endl;

    // Остальной код...
}
```


Соответствующий код инициализирует значение переменной определенным значением (в данном случае 0) перед ее использованием. Предоставляя начальное значение, мы обеспечиваем правильную инициализацию переменной и избегаем потенциальных проблем, связанных с чтением неинициализированной памяти.


Semgrep:


```
rules:
- id: uninitialized-variable
  pattern: $variable
  message: Potential uninitialized variable usage detected
```

CodeQL:



```
import cpp

from VariableAccess access
where not exists(access.getInitializer())
select access,
       "Potential uninitialized variable usage detected" as message
```





## Race Conditions


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```c
#include <iostream>
#include <thread>

int balance = 100;

void withdrawMoney(int amount) {
    if (balance >= amount) {
        // Имитация некоторой задержки или дорогостоящей операции
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        balance -= amount;
        std::cout << "Withdrawal successful. Remaining balance: " << balance << std::endl;
    } else {
        std::cout << "Insufficient balance." << std::endl;
    }
}

int main() {
    std::thread t1(withdrawMoney, 50);
    std::thread t2(withdrawMoney, 70);

    t1.join();
    t2.join();

    // Остальной код...
}
```

В коде, не соответствующем требованиям, два потока t1 и t2 одновременно обращаются к общей переменной balance и изменяют ее без надлежащей синхронизации. Это может привести к возникновению состояния гонки, когда результат работы программы становится недетерминированным и зависит от времени выполнения потоков. Это может привести к непоследовательным или неправильным результатам, таким как некорректное обновление баланса или повреждение данных.


<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```c
#include <iostream>
#include <thread>
#include <mutex>

int balance = 100;
std::mutex balanceMutex;

void withdrawMoney(int amount) {
    std::lock_guard<std::mutex> lock(balanceMutex);
    if (balance >= amount) {
        // Имитация некоторой задержки или дорогостоящей операции
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        balance -= amount;
        std::cout << "Withdrawal successful. Remaining balance: " << balance << std::endl;
    } else {
        std::cout << "Insufficient balance." << std::endl;
    }
}

int main() {
    std::thread t1(withdrawMoney, 50);
    std::thread t2(withdrawMoney, 70);

    t1.join();
    t2.join();

    // Остальная часть кода...
}
```


Соответствующий код решает проблему гонки путем введения мьютекса (balanceMutex) и использования защиты блокировки (std::lock_guard) для обеспечения эксклюзивного доступа к критической секции, в которой изменяется переменная balance. Мьютекс гарантирует, что только один поток может получить доступ к критической секции одновременно, предотвращая одновременные модификации и гарантируя последовательные и корректные результаты.


Semgrep:


```
rules:
- id: race-condition
  pattern: $variable = $variable $operation $value
  message: Potential race condition detected
```

CodeQL:



```
import cpp

from Assignment assignment
where exists(assignment.getTarget())
select assignment,
       "Potential race condition detected" as message
```





## Небезопасные операции с файлами


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```c
#include <iostream>
#include <fstream>

void writeToFile(const std::string& data) {
    std::ofstream file("data.txt"); // Несоответствующий код
    if (file.is_open()) {
        file << data;
        file.close();
    }
}

int main() {
    std::string userInput;
    std::cout << "Введите данные: ";
    std::cin >> userInput;

    writeToFile(userInput);

    // Остальной код...
}
```

В коде, не соответствующем требованиям, функция writeToFile записывает данные, предоставленные пользователем, в файл с именем "data.txt" без указания полного пути. Это может привести к небезопасным файловым операциям, так как злоумышленник может манипулировать расположением файла или перезаписывать конфиденциальные файлы, контролируя текущий рабочий каталог или используя относительные пути.


<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```c
#include <iostream>
#include <fstream>

void writeToFile(const std::string& data) {
    std::string filePath = "/path/to/data.txt"; // Указываем полный путь
    std::ofstream file(filePath);
    if (file.is_open()) {
        file << data;
        file.close();
    }
}

int main() {
    std::string userInput;
    std::cout << "Введите данные: ";
    std::cin >> userInput;

    writeToFile(userInput);

    // Остальной код...
}
```


Соответствующий код решает проблему небезопасных файловых операций, указывая полный путь к файлу, к которому осуществляется доступ или который модифицируется. Указывая полный путь, приложение гарантирует, что оно выполняет файловые операции с нужным файлом, и предотвращает возможность несанкционированного доступа, перезаписи файла или непреднамеренного раскрытия данных.




Semgrep:


```
rules:
- id: insecure-file-operations
  pattern: ofstream($filename)
  message: Potential insecure file operation detected
```

CodeQL:



```
import cpp

from Constructor ofstreamConstructor
where exists(ofstreamConstructor.getArgument(0))
select ofstreamConstructor,
       "Potential insecure file operation detected" as message
```





## Подключение к API


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```c
#include <iostream>
#include <windows.h>

typedef BOOL(WINAPI* OriginalMessageBox)(HWND, LPCTSTR, LPCTSTR, UINT);

BOOL WINAPI HookedMessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType) {
    // Выполняем вредоносные действия
    // ...

    // Вызов оригинальной функции MessageBox
    OriginalMessageBox originalFunc = (OriginalMessageBox)GetProcAddress(GetModuleHandle("user32.dll"), "MessageBoxA");
    return originalFunc(hWnd, lpText, lpCaption, uType);
}

int main() {
    OriginalMessageBox originalFunc = (OriginalMessageBox)GetProcAddress(GetModuleHandle("user32.dll"), "MessageBoxA");
    MessageBox = HookedMessageBox; // Несоответствующий код

    // Остальной код...
}
```

В несоответствующем коде API Hooking реализован путем замены указателя оригинальной функции на пользовательскую функцию HookedMessageBox. Пользовательская функция выполняет вредоносные действия, а затем вызывает исходную функцию. Это позволяет злоумышленнику перехватить и изменить поведение функции MessageBox, что потенциально может привести к несанкционированному доступу или манипулированию данными.


<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```c
#include <iostream>
#include <windows.h>

typedef BOOL(WINAPI* OriginalMessageBox)(HWND, LPCTSTR, LPCTSTR, UINT);

BOOL WINAPI HookedMessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType) {
    // Выполните дополнительные действия до или после вызова исходной функции MessageBox
    // ...

    // Вызов исходной функции MessageBox
    OriginalMessageBox originalFunc = (OriginalMessageBox)GetProcAddress(GetModuleHandle("user32.dll"), "MessageBoxA");
    return originalFunc(hWnd, lpText, lpCaption, uType);
}

int main() {
    // Используем указатель оригинальной функции напрямую
    OriginalMessageBox originalFunc = (OriginalMessageBox)GetProcAddress(GetModuleHandle("user32.dll"), "MessageBoxA");
    originalFunc(NULL, "Hello", "Message", MB_OK);

    // Остальной код...
}
```


Соответствующий код не реализует API Hooking. Вместо этого он использует исходный указатель функции непосредственно для вызова функции MessageBox. Это гарантирует сохранение оригинального поведения API и предотвращает несанкционированный перехват или модификацию функции.



Semgrep:


```
rules:
- id: api-hooking
  pattern: $function = $hookFunction
  message: Potential API Hooking vulnerability detected
```

CodeQL:



```
import cpp

from FunctionPointerAssignment functionPointerAssignment
where exists(functionPointerAssignment.getTarget())
and exists(functionPointerAssignment.getAssignment())
select functionPointerAssignment,
       "Potential API Hooking vulnerability detected" as message
```








## TOCTOU


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```c
#include <iostream>
#include <fstream>

bool isFileWritable(const std::string& filename) {
    std::ofstream file(filename);
    return file.good(); // Несоответствующий код
}

int main() {
    std::string filename = "data.txt";
    if (isFileWritable(filename)) {
        std::ofstream file(filename);
        file << "Data"; // Несоответствующий код
        file.close();
        std::cout << "Файл записан успешно." << std::endl;
    } else {
        std::cout << "Файл не доступен для записи". << std::endl;
    }

    // Остальной код...
}
```

В коде, не соответствующем требованиям, функция isFileWritable пытается проверить, доступен ли файл для записи, создавая объект ofstream и проверяя его состояние. Однако между моментом проверки и моментом использования файла он может быть изменен извне. Это приводит к уязвимости Time-of-Check Time-of-Use (TOCTOU), поскольку состояние файла может измениться после выполнения проверки, но до того, как файл будет использован.


<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```c
#include <iostream>
#include <fstream>

bool isFileWritable(const std::string& filename) {
    std::ifstream file(filename);
    return file.good();
}

int main() {
    std::string filename = "data.txt";
    if (isFileWritable(filename)) {
        std::ofstream file(filename);
        file << "Data";
        file.close();
        std::cout << "Файл записан успешно." << std::endl;
    } else {
        std::cout << "Файл не доступен для записи". << std::endl;
    }

    // Остальной код...
}
```


Соответствующий код позволяет избежать уязвимости TOCTOU путем изменения потока кода. Вместо того чтобы проверять, доступен ли файл для записи, а затем выполнять операцию записи, он напрямую пытается открыть файл для записи. Если файл не доступен для записи, выполняется соответствующая обработка ошибки. Это устраняет промежуток между проверкой и использованием, когда состояние файла может измениться.


Semgrep:


```
rules:
- id: toctou
  pattern: |
    $check = $expr;
    $use
  message: Potential TOCTOU vulnerability detected
```

CodeQL:



```
import cpp

from Assignment assignment, MethodCall methodCall
where assignment.getTarget() = methodCall.getReturnedExpr()
  and methodCall.getName().getText() = "good"
select assignment,
       "Potential TOCTOU vulnerability detected" as message
```









