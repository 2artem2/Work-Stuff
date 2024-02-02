---
layout: default
title: C
parent: Rules
---

# C
{: .no_toc }


## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---




## Переполнение буфера

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```c
void copy_string(char* dest, char* src) {
  int i = 0;
  while(src[i] != '\0') {
    dest[i] = src[i];
    i++;
  }
  dest[i] = '\0';
}

int main() {
  char str1[6];
  char str2[10] = "example";
  copy_string(str1, str2);
  printf("%s", str1);
  return 0;
}
```

В этом примере функция `copy_string` копирует содержимое `src` в `dest`. Однако проверка длины dest отсутствует, и если src длиннее dest, произойдет переполнение буфера, что может привести к перезаписи соседних адресов памяти и неопределенному поведению. В данном случае длина строки str2 составляет 7 символов, поэтому вызов copy_string переполнит буфер строки str1, длина которой составляет всего 6.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```c
void copy_string(char* dest, char* src, size_t dest_size) {
  int i = 0;
  while(src[i] != '\0' && i < dest_size - 1) {
    dest[i] = src[i];
    i++;
  }
  dest[i] = '\0';
}

int main() {
  char str1[6];
  char str2[10] = "example";
  copy_string(str1, str2, sizeof(str1));
  printf("%s", str1);
  return 0;
}
```


В этом соответствующем коде функция `copy_string` принимает дополнительный параметр dest_size, который является максимальным размером буфера dest. Функция проверяет длину src на соответствие dest_size, чтобы избежать переполнения буфера. Для получения размера буфера dest используется оператор sizeof, поэтому он всегда корректно передается в copy_string. Используя параметр dest_size, код гарантирует, что он не запишет больше данных, чем может вместить буфер назначения, предотвращая переполнение буфера.




Semgrep:


```
rules:
  - id: buffer-overflow
    patterns:
      - pattern: 'while\(src\[i\] != \'\\0\'\)'
    message: "Potential buffer overflow vulnerability"
```

CodeQL:



```
import c

from Function f
where f.getName() = "copy_string"
select f
```








## Разыменование нулевого указателя


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```c
#include <stdio.h>

int main() {
    int* ptr = NULL;
    *ptr = 10; // Несоответствующий код

    // Остальной код...
}
```

В коде, не соответствующем требованиям, нулевой указатель ptr разыменовывается при попытке присвоить значение ячейке памяти, на которую он указывает. Это приводит к Null Pointer Dereference, поскольку разыменование нулевого указателя приводит к неопределенному поведению и потенциальным сбоям или уязвимостям безопасности.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```c
#include <stdio.h>

int main() {
    int value = 10;
    int* ptr = &value; // Присвоение адреса допустимой переменной

    *ptr = 20; // Допустимое присваивание

    // Остальной код...
}
```


Соответствующий код обеспечивает обращение к корректному участку памяти. В этом случае объявляется значение переменной и ее адрес присваивается указателю ptr. Разыменование ptr после указания на допустимую переменную обеспечивает корректный доступ к памяти.




Semgrep:


```
rules:
- id: null-pointer-dereference
  pattern: "*$expr"
  message: Potential null pointer dereference detected
```

CodeQL:



```
import c

from ExprDereference dereference
select dereference,
       "Potential null pointer dereference detected" as message
```






## Целочисленное переполнение/недополнение


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```c
#include <stdio.h>

int main() {
    int a = 2147483647; // Максимальное значение для знакового int
    int b = 1;
    int result = a + b; // Несоответствующий код

    printf("Результат: %d\n", result);

    // Остальная часть кода...
}
```

В коде, не соответствующем требованиям, происходит целочисленное переполнение при сложении максимального значения для знакового целого (a) с 1 (b). Результат превышает максимальное значение, которое может быть представлено знаковым целым, что приводит к неопределенному поведению и потенциально некорректным вычислениям или уязвимостям безопасности.





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```c
#include <stdio.h>
#include <limits.h>

int main() {
    int a = INT_MAX;
    int b = 1;

    if (a <= INT_MAX - b) {
        int result = a + b;
        printf("Result: %d\n", result);
    } else {
        printf("Overflow occurred.\n");
    }

    // Остальная часть кода...
}
```


Соответствующий код проверяет условие потенциального переполнения перед выполнением сложения. Он проверяет, останется ли результат в пределах диапазона представимых значений для знакового int, сравнивая a с INT_MAX - b. Если условие истинно, сложение выполняется, и результат выводится на печать. В противном случае может быть реализована соответствующая обработка ситуации переполнения.




Semgrep:


```
rules:
- id: integer-overflow
  pattern: "$var + $expr"
  message: Potential integer overflow detected
```

CodeQL:



```
import c

from BinaryExpr addition
where addition.getOperator() = "+"
select addition,
       "Potential integer overflow detected" as message
```




## Отказ в обслуживании (DoS)


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```c
#include <stdio.h>

void processRequest(int length, char* request) {
    // Обрабатываем запрос без какой-либо проверки или ограничения скорости.
    // Этот код может потреблять чрезмерное количество ресурсов и вызвать состояние DoS
}

int main() {
    int length = 1000000000; // Большое значение для имитации потенциально вредоносного запроса
    char* request = (char*)malloc(length * sizeof(char));
    // Заполняем буфер запроса данными

    processRequest(length, request);

    // Остальной код...
    free(request);
}
```

В коде, не соответствующем требованиям, создается потенциально вредоносный большой запрос с очень большим значением длины. Затем запрос передается в функцию processRequest без какой-либо проверки или ограничения скорости. Это может вызвать чрезмерное потребление программой ресурсов, что приведет к отказу в обслуживании (DoS), когда система перестанет отвечать на запросы или завершится аварийно.







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```c
#include <stdio.h>

void processRequest(int length, char* request) {
    // Внедрите соответствующие механизмы проверки запросов и ограничения скорости.
    // для предотвращения DoS-атак
    // Обрабатывайте запрос только в том случае, если он соответствует заданным критериям
}

int main() {
    int length = 1000000000; // Большое значение для имитации потенциально вредоносного запроса
    char* request = (char*)malloc(length * sizeof(char));
    // Заполняем буфер запроса данными

    // Выполняем проверку запроса на валидность и ограничение скорости перед обработкой
    if (length <= MAX_REQUEST_LENGTH) {
        processRequest(length, request);
    } else {
        printf("Запрос слишком большой. Игнорирование...\n");
    }

    // Остальная часть кода...
    free(request);
}
```


Соответствующий код реализует соответствующие механизмы проверки запросов и ограничения скорости для предотвращения DoS-атак. В этом примере определена максимальная длина запроса (MAX_REQUEST_LENGTH), и длина запроса проверяется перед обработкой. Если длина превышает установленный предел, запрос игнорируется и выводится соответствующее сообщение.



Semgrep:


```
rules:
- id: dos-attack
  pattern: malloc($size * sizeof($type))
  message: Potential DoS vulnerability detected
```

CodeQL:



```
import c

from CallExpr mallocCall
where mallocCall.getTarget().toString() = "malloc"
select mallocCall,
       "Potential DoS vulnerability detected" as message
```







## Формат String


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```c
#include <stdio.h>

int main() {
    char name[100];
    printf("Введите ваше имя: ");
    scanf("%s", name);

    printf(name); // Несоответствующий код, уязвимость форматной строки

    // Остальной код...
}
```

В коде, не соответствующем требованиям, пользовательский ввод напрямую передается в функцию printf без надлежащей обработки форматной строки. Это может привести к уязвимости Format String, когда злоумышленник может контролировать аргумент форматной строки и потенциально эксплуатировать программу, получая доступ или изменяя непредусмотренные адреса памяти.






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```c
#include <stdio.h>

int main() {
    char name[100];
    printf("Введите ваше имя: ");
    scanf("%99s", name);

    printf("%s", name); // Соответствующий код, правильное использование строки формата

    // Остальная часть кода...
}
```


Соответствующий код обеспечивает правильную обработку пользовательского ввода, указывая максимальную ширину поля в функции scanf для предотвращения переполнения буфера. Затем пользовательский ввод выводится на печать с использованием спецификатора формата %s в функции printf, что обеспечивает правильное использование строки формата.


Semgrep:


```
rules:
- id: format-string-vulnerability
  pattern: "printf($expr)"
  message: Potential format string vulnerability detected
```

CodeQL:



```
import c

from CallExpr printfCall
where printfCall.getTarget().toString() = "printf"
select printfCall,
       "Potential format string vulnerability detected" as message
```




## Небезопасная криптография


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```c
#include <stdio.h>
#include <openssl/md5.h>

void insecureHashPassword(const char* password) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((unsigned char*)password, strlen(password), digest);
    // Небезопасно: использование MD5 для хеширования пароля

    // Остальной код...
}

int main() {
    const char* password = "mysecretpassword";
    insecureHashPassword(password);

    // Остальной код...
}
```

В несоответствующем коде для хэширования паролей используется криптографическая хэш-функция MD5. MD5 считается небезопасным алгоритмом хэширования паролей из-за его уязвимости к различным атакам, таким как атаки на столкновение и атаки на предварительный образ. Для хранения паролей необходимо использовать более надежные и безопасные хэш-алгоритмы.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```c
#include <stdio.h>
#include <openssl/sha.h>

void secureHashPassword(const char* password) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)password, strlen(password), digest);
    // Безопасность: использование SHA-256 для хэширования паролей

    // Остальной код...
}

int main() {
    const char* password = "mysecretpassword";
    secureHashPassword(password);

    // Остальной код...
}
```


Соответствующий код заменяет использование небезопасной хэш-функции MD5 на более безопасную хэш-функцию SHA-256. SHA-256 - это более сильный криптографический алгоритм, который подходит для хэширования паролей и обеспечивает лучшую защиту от различных атак.


Semgrep:


```
rules:
- id: insecure-cryptography
  patterns:
    - "MD5($expr)"
    - "SHA1($expr)"
  message: Potential insecure cryptography usage detected
```

CodeQL:



```
import c

from CallExpr md5Call, sha1Call
where md5Call.getTarget().toString() = "MD5"
   or sha1Call.getTarget().toString() = "SHA1"
select md5Call, sha1Call,
       "Potential insecure cryptography usage detected" as message
```






## Повреждение памяти

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void copyData(char* dest, const char* src, size_t size) {
    memcpy(dest, src, size);
    // Несоответствующий код: потенциальное повреждение памяти, если размер больше, чем выделено памяти для dest

    // Остальной код...
}

int main() {
    char buffer[10];
    const char* data = "Hello, World!";

    copyData(buffer, data, strlen(data) + 1);

    // Остальной код...
}
```

В коде, не соответствующем требованиям, функция copyData использует функцию memcpy для копирования данных из исходного буфера в буфер назначения. Однако если размер данных превышает объем памяти, выделенной для буфера назначения, это может привести к повреждению памяти и неожиданному поведению, включая сбои или уязвимости безопасности.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void copyData(char* dest, const char* src, size_t size) {
    size_t destSize = sizeof(dest); // Вычисляем размер буфера назначения
    if (size > destSize) {
        // Обработать условие ошибки соответствующим образом (например, усечь, вернуть код ошибки и т. д.)
        return;
    }

    memcpy(dest, src, size);
    // Соответствующий код: гарантирует, что размер исходных данных не превышает размер памяти, выделенной для dest

    // Остальной код...
}

int main() {
    char buffer[10];
    const char* data = "Hello, World!";

    copyData(buffer, data, strlen(data) + 1);

    // Остальной код...
}
```


Соответствующий код вводит проверку, чтобы убедиться, что размер исходных данных не превышает объем памяти, выделенной для буфера назначения. Если размер превышает объем буфера назначения, код может соответствующим образом обработать условие ошибки, например, усечь данные, вернуть код ошибки или предпринять другие необходимые действия.


Semgrep:


```
rules:
- id: memory-corruption
  pattern: memcpy($dest, $src, $size)
  message: Potential memory corruption detected
```

CodeQL:



```
import c

from CallExpr memcpyCall
where memcpyCall.getTarget().toString() = "memcpy"
select memcpyCall,
       "Potential memory corruption detected" as message
```





## Code Injection


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```c
#include <stdio.h>
#include <stdlib.h>

void executeCommand(const char* command) {
    char buffer[100];
    snprintf(buffer, sizeof(buffer), "system(\"%s\")", command);
    system(buffer);
    // Несоответствующий код: потенциальная уязвимость инъекции кода

    // Остальной код...
}

int main() {
    const char* userInput = "ls -la";
    executeCommand(userInput);

    // Остальной код...
}
```

В коде, не соответствующем требованиям, функция executeCommand строит командную строку, напрямую объединяя пользовательский ввод с системной командой. Это может привести к уязвимости инъекции кода, когда злоумышленник может манипулировать вводом для выполнения произвольных команд в системе.




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```c
#include <stdio.h>
#include <stdlib.h>

void executeCommand(const char* command) {
    // Выполните соответствующую проверку и санацию ввода.
    // для обеспечения целостности команды

    system(command);
    // Соответствующий код: выполнение команды напрямую без манипуляций со строкой

    // Остальной код...
}

int main() {
    const char* userInput = "ls -la";
    executeCommand(userInput);

    // Остальной код...
}
```


Соответствующий код выполняет проверку и санацию ввода для обеспечения целостности выполняемой команды. Он избегает манипулирования строками и выполняет команду напрямую, снижая риск возникновения уязвимостей, связанных с инъекцией кода.



Semgrep:


```
rules:
- id: code-injection
  pattern: "system($expr)"
  message: Potential code injection vulnerability detected
```

CodeQL:



```
import c

from CallExpr systemCall
where systemCall.getTarget().toString() = "system"
select systemCall,
       "Potential code injection vulnerability detected" as message
```




## Перехват DLL


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```c
#include <windows.h>

void loadDLL(const char* dllName) {
    HMODULE hModule = LoadLibraryA(dllName);
    // Несоответствующий код: загрузка DLL без указания абсолютного пути

    // Остальной код...
}

int main() {
    const char* dllName = "mydll.dll";
    loadDLL(dllName);

    // Остальной код...
}
```

В коде, не соответствующем требованиям, функция loadDLL загружает DLL с помощью функции LoadLibraryA, не указывая абсолютный путь к DLL. Это может привести к уязвимости перехвата DLL, когда злоумышленник может поместить вредоносную DLL с тем же именем в место поиска приложения, что приведет к выполнению непреднамеренного кода.



<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```c
#include <windows.h>
#include <stdbool.h>

bool isValidDLLPath(const char* dllPath) {
    // Выполняет соответствующую проверку, чтобы убедиться, что путь к DLL является надежным.

    // Возвращает true, если путь к DLL является действительным, false - в противном случае
    return true;
}

void loadDLL(const char* dllName) {
    char dllPath[MAX_PATH];
    // Строим абсолютный путь к DLL, используя доверенное местоположение
    snprintf(dllPath, sizeof(dllPath), "C:\\Path\\To\\DLLs\\\%s", dllName);

    if (!isValidDLLPath(dllPath)) {
        // Обработать условие ошибки соответствующим образом (например, записать в журнал, вернуть и т. д.)
        return;
    }

    HMODULE hModule = LoadLibraryA(dllPath);
    // Соответствующий код: загрузка DLL с абсолютным путем

    // Остальной код...
}

int main() {
    const char* dllName = "mydll.dll";
    loadDLL(dllName);

    // Остальной код...
}
```


Соответствующий код обеспечивает загрузку DLL с использованием абсолютного пути к DLL-файлу. Он строит абсолютный путь, используя доверенное местоположение, и выполняет соответствующую проверку (isValidDLLPath), чтобы убедиться, что путь DLL является доверенным, прежде чем загрузить DLL.


Semgrep:


```
rules:
- id: dll-hijacking
  patterns:
    - "LoadLibraryA($dllName)"
    - "LoadLibraryW($dllName)"
  message: Potential DLL hijacking vulnerability detected
```

CodeQL:



```
import cpp

from CallExpr loadLibraryCall
where loadLibraryCall.getTarget().toString() = "LoadLibraryA"
   or loadLibraryCall.getTarget().toString() = "LoadLibraryW"
select loadLibraryCall,
       "Potential DLL hijacking vulnerability detected" as message
```





## Использовать после бесплатно


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Noncompliant code:


```c
#include <stdlib.h>

void useAfterFree() {
    int* ptr = (int*)malloc(sizeof(int));
    free(ptr);
    *ptr = 42; // Несоответствующий код: использование после освобождения

    // Остальной код...
}

int main() {
    useAfterFree();

    // Остальной код...
}
```

В коде, не соответствующем требованиям, функция useAfterFree выделяет память с помощью malloc, но затем сразу же освобождает ее с помощью free. После этого она пытается разыменовать освобожденный указатель, что приводит к неопределенному поведению и потенциальной уязвимости use after free.


<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```c
#include <stdlib.h>

void useAfterFree() {
    int* ptr = (int*)malloc(sizeof(int));
    if (ptr == NULL) {
        // Обработать сбой выделения соответствующим образом (например, вернуть, записать в журнал и т.д.)
        return;
    }

    *ptr = 42;
    // Соответствующий код: использование выделенной памяти перед ее освобождением

    free(ptr);

    // Остальной код...
}

int main() {
    useAfterFree();

    // Остальной код...
}
```


Соответствующий код гарантирует, что выделенная память будет использована до ее освобождения. Он выполняет соответствующие проверки на сбой выделения и обрабатывает его соответствующим образом, чтобы избежать уязвимостей использования после освобождения.


Semgrep:


```
rules:
- id: use-after-free
  pattern: "free($expr); $expr ="
  message: Potential use after free vulnerability detected
```

CodeQL:



```
import cpp

from ExprStmt freeStmt, assignment
where freeStmt.getExpr().toString().matches("^free\\(.*\\)$")
  and assignment.toString().matches("^.* = .*")
  and assignment.getExpr().toString() = freeStmt.getExpr().toString()
select freeStmt,
       "Potential use after free vulnerability detected" as message
```






## Неинициализированные переменные


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```c
#include <stdio.h>

int getValue() {
    int value; // Несоответствующий код: неинициализированная переменная

    // Выполните некоторые операции или вычисления для инициализации значения

    возвращаем значение;
}

int main() {
    int result = getValue();
    printf("Результат: %d\n", result);

    // Остальной код...
}
```

В коде, не соответствующем требованиям, значение переменной объявляется, но не инициализируется перед использованием в функции getValue. Это может привести к неопределенному поведению и неправильным результатам при обращении к неинициализированной переменной.


<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```c
#include <stdio.h>

int getValue() {
    int value = 0; // Соответствующий код: инициализация переменной

    // Выполните некоторые операции или вычисления для инициализации значения

    возвращаем значение;
}

int main() {
    int result = getValue();
    printf("Результат: %d\n", result);

    // Остальной код...
}
```


Соответствующий код инициализирует значение переменной известным значением (в данном случае 0) перед ее использованием. Это гарантирует, что переменная имеет определенное значение, и предотвращает потенциальные проблемы, вызванные неинициализированными переменными.


Semgrep:


```
rules:
- id: uninitialized-variable
  pattern: "$type $varName;"
  message: Potential uninitialized variable detected
```

CodeQL:



```
import cpp

from VariableDeclarator uninitializedVariable
where not uninitializedVariable.hasInitializer()
select uninitializedVariable,
       "Potential uninitialized variable detected" as message
```





## Race Conditions


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```c
#include <stdio.h>
#include <pthread.h>

int counter = 0;

void* incrementCounter(void* arg) {
    for (int i = 0; i < 1000; ++i) {
        counter++; // Несоответствующий код: состояние гонки
    }

    return NULL;
}

int main() {
    pthread_t thread1, thread2;

    pthread_create(&thread1, NULL, incrementCounter, NULL);
    pthread_create(&thread2, NULL, incrementCounter, NULL);

    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);

    printf("Значение счетчика: %d\n", counter);

    // Остальной код...
}
```

В коде, не соответствующем требованиям, создаются два потока для увеличения общей переменной-счетчика. Однако, поскольку инкремент не синхронизирован, возникает состояние гонки, когда потоки могут мешать друг другу, что приводит к непредсказуемым и неправильным результатам.


<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```c
#include <stdio.h>
#include <pthread.h>

int counter = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

void* incrementCounter(void* arg) {
    for (int i = 0; i < 1000; ++i) {
        pthread_mutex_lock(&mutex); // Получение блокировки
        counter++; // Соответствующий код: синхронизированный доступ к счетчику
        pthread_mutex_unlock(&mutex); // Освобождение блокировки
    }

    return NULL;
}

int main() {
    pthread_t thread1, thread2;

    pthread_create(&thread1, NULL, incrementCounter, NULL);
    pthread_create(&thread2, NULL, incrementCounter, NULL);

    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);

    printf("Значение счетчика: %d\n", counter);

    // Остальной код...
}
```


Соответствующий код вводит мьютекс (pthread_mutex_t) для синхронизации доступа к переменной счетчика. Мьютекс блокируется перед обращением к счетчику и разблокируется после этого, гарантируя, что только один поток может изменять счетчик одновременно, устраняя условие гонки.



Semgrep:


```
rules:
- id: race-condition
  pattern: |
    $lockPattern($lockVar);
    $varName $incOp
  message: Potential race condition detected
```

CodeQL:



```
import cpp

from LockExpr lockExpr, PostfixIncExpr postfixInc
where lockExpr.getLockVar().getType().toString() = "pthread_mutex_t *"
  and lockExpr.getLockPattern().toString() = "pthread_mutex_lock"
  and postfixInc.getOperand().toString() = lockExpr.getLockVar().toString()
select lockExpr,
       "Potential race condition detected" as message
```





## Небезопасные операции с файлами


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```c
#include <stdio.h>

void readFile(const char* filename) {
    FILE* file = fopen(filename, "r"); // Несоответствующий код: небезопасная работа с файлом

    if (file != NULL) {
        // Считываем содержимое файла

        fclose(file);
    }
}

int main() {
    const char* filename = "sensitive.txt";
    readFile(filename);

    // Остальной код...
}
```

В коде, не соответствующем требованиям, функция readFile использует функцию fopen для открытия файла в режиме чтения. Однако она не выполняет валидацию и не проверяет ошибки, что может привести к уязвимостям безопасности. Злоумышленник может манипулировать аргументом filename, чтобы получить доступ к нежелательным файлам или каталогам.


<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```c
#include <stdio.h>

void readFile(const char* filename) {
    if (filename == NULL) {
        // Обработайте неправильное имя файла соответствующим образом (например, return, log и т.д.)
        return;
    }

    FILE* file = fopen(filename, "r");
    if (file != NULL) {
        // Считываем содержимое файла

        fclose(file);
    }
}

int main() {
    const char* filename = "sensitive.txt";
    readFile(filename);

    // Остальной код...
}
```


Соответствующий код включает проверку того, что аргумент filename не является NULL перед выполнением операции с файлом. Кроме того, для снижения потенциальных рисков безопасности реализованы обработка ошибок и надлежащее закрытие файла.




Semgrep:


```
rules:
- id: insecure-file-operation
  pattern: "fopen($filename, $mode);"
  message: Potential insecure file operation detected
```

CodeQL:



```
import cpp

from CallExpr fopenCall
where fopenCall.getTarget().getName() = "fopen"
  and exists(ExceptionalControlFlow ecf |
    ecf.getAnomalyType() = "ANOMALY_UNCHECKED_RETURN_VALUE"
    and ecf.getAnomalySource() = fopenCall
  )
select fopenCall,
       "Potential insecure file operation detected" as message
```





## Подключение к API

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```c
#include <stdio.h>
#include <windows.h>

void hookFunction() {
    // Код хука здесь
    // ...
}

int main() {
    // Оригинальный код функции здесь
    // ...

    hookFunction();

    // Остальной код...
}
```

В несоответствующем коде функция hookFunction используется для изменения или замены поведения исходной функции. Эта техника широко известна как API hooking и часто используется в злонамеренных целях, таких как перехват конфиденциальных данных или вмешательство в работу системы. Несоответствующий код не имеет надлежащей авторизации и контроля над процессом подключения.

<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```c
#include <stdio.h>

void originalFunction() {
    // Оригинальный код функции здесь
    // ...
}

void hookFunction() {
    // Код хука здесь
    // ...
}

int main() {
    // Оригинальный код функции здесь
    // ...

    // Вызываем исходную функцию
    originalFunction();

    // Остальной код...
}
```


Соответствующий код разделяет исходную функцию (originalFunction) и логику подцепления (hookFunction) на отдельные функции. Вместо того чтобы напрямую подключать оригинальную функцию, соответствующий код вызывает саму оригинальную функцию, обеспечивая требуемое поведение и предотвращая несанкционированную модификацию.




Semgrep:


```
rules:
- id: api-hooking
  pattern: |
    $hookFunc:ident();
  message: Potential API hooking detected
```

CodeQL:



```
import cpp

from CallExpr hookFuncCall
where hookFuncCall.getTarget().getName() = "hookFunction"
select hookFuncCall,
       "Potential API hooking detected" as message
```








## TOCTOU


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```c
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

void processFile(const char* filename) {
    struct stat fileStat;
    stat(filename, &fileStat); // Время проверки

    // Имитируем задержку между временем проверки и временем использования
    sleep(1);

    if (S_ISREG(fileStat.st_mode)) {
        // Выполняем операции над обычными файлами
        // ...
    }
}

int main() {
    const char* filename = "data.txt";
    processFile(filename);

    // Остальной код...
}
```

В несоответствующем коде функция processFile проверяет свойства файла с помощью функции stat (Time-of-Check). Однако с помощью функции sleep вводится задержка, что создает возможность для злоумышленника изменить или заменить файл до наступления времени использования. Это может привести к уязвимостям в системе безопасности, когда может быть обработан не тот файл.


<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```c
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

void processFile(const char* filename) {
    struct stat fileStat;

    // Выполняем проверку и использование времени атомарно
    if (stat(filename, &fileStat) == 0 && S_ISREG(fileStat.st_mode)) {
        // Выполняем операции над обычными файлами
        // ...
    }
}

int main() {
    const char* filename = "data.txt";
    processFile(filename);

    // Остальной код...
}
```


Соответствующий код выполняет проверку и использование времени атомарно в функции processFile. Он проверяет возвращаемое значение функции stat, чтобы убедиться, что она успешно выполнилась, а затем проверяет свойства файла. Устраняя задержку между Time-of-Check и Time-of-Use, соответствующий код устраняет уязвимость TOCTOU.


Semgrep:


```
rules:
- id: toctou
  pattern: |
    $checkStat:stat($filename, $_);
    sleep($delay);
    if ($checkStat && S_ISREG($_.st_mode)) {
      // Уязвимый код здесь
      // ...
    }
  message: Potential TOCTOU vulnerability detected
```

CodeQL:



```
import cpp

from CallExpr statCall, SleepExpr sleepExpr, Expr statArg
where statCall.getTarget().getName() = "stat"
  and sleepExpr.getArgument() = $delay
  and statArg.getType().toString() = "struct stat *"
  and exists(ControlFlowNode statNode |
    statNode.asExpr() = statCall
    and exists(ControlFlowNode sleepNode |
      sleepNode.asExpr() = sleepExpr
      and sleepNode < statNode
    )
  )
  and exists(Expr fileStat |
    fileStat.getType().getName() = "struct stat"
    and exists(ControlFlowNode useNode |
      useNode.asExpr() = fileStat
      and useNode > statNode
      and useNode < sleepNode
      and useNode.(CallExpr).getTarget().getName() = "
```







