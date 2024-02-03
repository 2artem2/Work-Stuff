---
layout: default
title: Go
parent: Rules
---

# Go
{: .no_toc }


## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---





## Раскрытие конфиденциальной информации

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/users", getUsers)
	http.ListenAndServe(":8080", nil)
}

func getUsers(w http.ResponseWriter, r *http.Request) {
	// Доступ к конфиденциальным данным из базы данных
	username := "admin"
	password := "secret"

	// Верните конфиденциальную информацию в HTTP-ответе
	fmt.Fprintf(w, "Username: %s, Password: %s", username, password)
}

```

В этом коде, не соответствующем требованиям, функция getUsers извлекает из базы данных конфиденциальную информацию, такую как имя пользователя и пароль. Однако код напрямую раскрывает эту конфиденциальную информацию в HTTP-ответе, возвращая ее как часть тела ответа. Это может привести к раскрытию учетных данных и других конфиденциальных сведений потенциальным злоумышленникам.

Чтобы решить эту проблему, приведем пример совместимого кода, который позволяет избежать раскрытия конфиденциальной информации:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/users", getUsers)
	http.ListenAndServe(":8080", nil)
}

func getUsers(w http.ResponseWriter, r *http.Request) {
	// Доступ к конфиденциальным данным из базы данных
	username := "admin"
	password := "secret"

	// Вместо того чтобы возвращать конфиденциальную информацию, верните общее сообщение
	fmt.Fprint(w, "Access denied")
}
```


В соответствующем коде функция getUsers по-прежнему извлекает конфиденциальную информацию из базы данных, но вместо того, чтобы возвращать ее в HTTP-ответе, возвращается общее сообщение. Это гарантирует, что конфиденциальная информация не попадет к потенциальным злоумышленникам.




## Вставка конфиденциальной информации в отправленные данные

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/login", login)
	http.ListenAndServe(":8080", nil)
}

func login(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Аутентификация пользователя
	if !authenticate(username, password) {
		errMsg := fmt.Sprintf("Login failed for user: %s", username)
		log.Println(errMsg)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// При успешном входе в систему
	// ...
	// Код для обработки успешного входа в систему
}

func authenticate(username, password string) bool {
	// Выполните логику аутентификации
	// ...
	// Код для аутентификации пользователя

	return false
}
```

В этом несоответствующем коде, когда учетные данные, предоставленные пользователем, не проходят аутентификацию, код регистрирует конфиденциальную информацию (имя пользователя) вместе с сообщением об ошибке. Сообщение об ошибке отправляется в качестве ответа клиенту. Такая практика может привести к тому, что конфиденциальная информация может стать доступной злоумышленнику и помочь в дальнейшей эксплуатации.

Чтобы решить эту проблему, вот пример совместимого кода, который позволяет избежать вставки конфиденциальной информации в отправленные данные через ошибку:




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
package main

import (
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/login", login)
	http.ListenAndServe(":8080", nil)
}

func login(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Аутентификация пользователя
	if !authenticate(username, password) {
		log.Println("Login failed for user:", username)
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// При успешном входе в систему
	// ...
	// Код для обработки успешного входа в систему
}

func authenticate(username, password string) bool {
	// Выполните логику аутентификации
	// ...
	// Код для аутентификации пользователя

	return false
}
```


В соответствующем коде конфиденциальная информация (имя пользователя) регистрируется без какого-либо конкретного сообщения об ошибке. Вместо этого в качестве ответа клиенту отправляется общее сообщение об ошибке, чтобы избежать раскрытия конфиденциальной информации. Это помогает защититься от уязвимостей, связанных с раскрытием информации.





## Подделка межсайтовых запросов (CSRF)

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
)

var (
	templates = template.Must(template.ParseFiles("index.html"))
)

func main() {
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/transfer", transferHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		templates.ExecuteTemplate(w, "index.html", nil)
	} else if r.Method == http.MethodPost {
		amount := r.FormValue("amount")
		account := r.FormValue("account")

		// Выполните перевод денег
		if transferMoney(amount, account) {
			fmt.Fprintln(w, "Transfer successful!")
		} else {
			fmt.Fprintln(w, "Transfer failed!")
		}
	}
}

func transferHandler(w http.ResponseWriter, r *http.Request) {
	// Обработать запрос на передачу данных
	// ...
}

func transferMoney(amount, account string) bool {
	// Выполните логику перевода денег
	// ...
	return false
}
```

В этом несовместимом коде не реализована защита от CSRF. Функция indexHandler обрабатывает как GET-, так и POST-запросы. При получении POST-запроса она выполняет перевод денег на основе значений, указанных в форме. Этот код уязвим для CSRF-атак, поскольку в нем нет механизма проверки происхождения запроса, что позволяет злоумышленникам создавать вредоносные запросы и выполнять несанкционированные переводы от имени аутентифицированного пользователя.

Чтобы решить эту проблему, вот пример совместимого кода, включающего защиту от CSRF:


<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/gorilla/csrf"
)

var (
	templates = template.Must(template.ParseFiles("index.html"))
)

func main() {
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/transfer", transferHandler)
	log.Fatal(http.ListenAndServe(":8080", csrf.Protect([]byte("32-byte-long-auth-key"))(nil)))
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		token := csrf.Token(r)
		data := struct {
			Token string
		}{
			Token: token,
		}
		templates.ExecuteTemplate(w, "index.html", data)
	} else if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}

		// Проверяем токен CSRF
		if err := csrf.Protect([]byte("32-byte-long-auth-key")).VerifyToken(csrf.Token(r)); err != nil {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}

		amount := r.FormValue("amount")
		account := r.FormValue("account")

		// Выполните перевод денег
		if transferMoney(amount, account) {
			fmt.Fprintln(w, "Transfer successful!")
		} else {
			fmt.Fprintln(w, "Transfer failed!")
		}
	}
}

func transferHandler(w http.ResponseWriter, r *http.Request) {
	// Обработать запрос на передачу данных
	// ...
}

func transferMoney(amount, account string) bool {
	// Выполните логику перевода денег
	// ...
	return false
}
```


В коде, соответствующем требованиям, для добавления защиты от CSRF используется пакет Gorilla CSRF (github.com/gorilla/csrf). Токен CSRF генерируется в функции indexHandler и включается в данные шаблона. На форме





## Использование жесткого пароля

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
package main

import (
	"fmt"
	"log"
)

func main() {
	password := "myHardcodedPassword"
	
	// Остальной код
	// ...
	
	// Аутентификация пользователя с жестко заданным паролем
	if authenticateUser(password) {
		fmt.Println("Authentication successful!")
	} else {
		fmt.Println("Authentication failed!")
	}
}

func authenticateUser(password string) bool {
	// Выполните логику аутентификации
	// ...
	return password == "myHardcodedPassword"
}
```

В этом несоответствующем коде пароль напрямую присваивается переменной password в виде жестко закодированной строки. Это уязвимость безопасности, поскольку пароль легко доступен в исходном коде. Если злоумышленник получит доступ к исходному коду, он сможет легко получить пароль и потенциально скомпрометировать систему.

Чтобы решить эту проблему, приведем пример совместимого кода, который позволяет избежать жесткого кодирования паролей:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
package main

import (
	"fmt"
	"log"
	"os"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	// Предложите пользователю ввести пароль
	password := promptPassword("Enter your password: ")

	// Остальной код
	// ...

	// Аутентификация пользователя с введенным паролем
	if authenticateUser(password) {
		fmt.Println("Authentication successful!")
	} else {
		fmt.Println("Authentication failed!")
	}
}

func promptPassword(prompt string) string {
	fmt.Print(prompt)
	password, _ := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	return string(password)
}

func authenticateUser(password string) bool {
	// Выполните логику аутентификации
	// ...
	return password == "correctPassword"
}
```

В соответствующем коде пароль больше не вводится жестко. Вместо этого используется функция promptPassword, которая безопасно предлагает пользователю ввести пароль. Функция terminal.ReadPassword используется для считывания пароля с терминала, не передавая его обратно эхом. Таким образом, пароль остается скрытым во время ввода и не виден непосредственно в коде. Функция authenticateUser сравнивает введенный пароль с правильным паролем, хранящимся в другом месте (например, в защищенной базе данных), чтобы выполнить процесс аутентификации.






## Сломанный или рискованный криптоалгоритм

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
package main

import (
	"crypto/md5"
	"fmt"
)

func main() {
	data := "Hello, World!"
	hash := md5.Sum([]byte(data))
	fmt.Printf("MD5 Hash: %x\n", hash)
}
```


В этом несовместимом коде для вычисления хэша заданной строки используется алгоритм MD5 из пакета crypto/md5. Однако MD5 считается нерабочим и небезопасным для криптографических целей из-за значительных уязвимостей, включая атаки на столкновения. Использование MD5 для хэширования конфиденциальной информации может подвергнуть систему различным рискам безопасности.

Чтобы решить эту проблему, приведем пример соответствующего кода, в котором используется более сильный криптографический алгоритм:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
package main

import (
	"crypto/sha256"
	"fmt"
)

func main() {
	data := "Hello, World!"
	hash := sha256.Sum256([]byte(data))
	fmt.Printf("SHA-256 Hash: %x\n", hash)
}
```

В соответствующем коде вместо MD5 используется алгоритм SHA-256 из пакета crypto/sha256. SHA-256 считается более сильным криптографическим алгоритмом и обеспечивает лучшую безопасность при хэшировании конфиденциальной информации. Используя SHA-256, код снижает риск, связанный со сломанными или рискованными криптоалгоритмами, и обеспечивает целостность и безопасность хэшированных данных.






## Недостаточная энтропия

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
package main

import (
	"fmt"
	"math/rand"
)

func generateToken() string {
	charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	length := 8
	token := ""

	for i := 0; i < length; i++ {
		index := rand.Intn(len(charset))
		token += string(charset[index])
	}

	return token
}

func main() {
	token := generateToken()
	fmt.Println("Generated Token:", token)
}
```


В этом несоответствующем коде функция generateToken() используется для генерации случайного маркера длиной 8 символов. Однако генератор случайных чисел rand.Intn() из пакета math/rand используется без достаточной энтропии. Пакет math/rand полагается на генератор псевдослучайных чисел (ГПСЧ), который выдает детерминированные результаты на основе значения затравки. В данном случае, поскольку семя не задано явно, ГПСЧ использует значение семени по умолчанию, что может привести к предсказуемому и неслучайному результату.


Чтобы решить эту проблему, приведем пример совместимого кода, который использует пакет crypto/rand для генерации случайного токена с достаточной энтропией:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func generateToken() string {
	length := 8
	tokenBytes := make([]byte, length)

	_, err := rand.Read(tokenBytes)
	if err != nil {
		panic(err)
	}

	token := base64.URLEncoding.EncodeToString(tokenBytes)[:length]
	return token
}

func main() {
	token := generateToken()
	fmt.Println("Generated Token:", token)
}
```

В соответствующем коде пакет crypto/rand используется вместе с функцией rand.Read() для генерации случайных байтов с достаточной энтропией. Затем эти случайные байты кодируются с помощью кодировки base64 для генерации случайного маркера. Использование пакета crypto/rand гарантирует использование безопасного генератора случайных чисел, который обеспечивает достаточную энтропию для генерации непредсказуемых и безопасных токенов.






## XSS

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
)

func handleHello(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	message := fmt.Sprintf("Hello, %s!", name)

	template := `<h1>Welcome</h1>
				 <p>%s</p>`

	output := fmt.Sprintf(template, message)
	fmt.Fprint(w, output)
}

func main() {
	http.HandleFunc("/hello", handleHello)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

В этом не соответствующем требованиям коде функция handleHello обрабатывает маршрут "/hello" и извлекает значение параметра запроса "name" из URL. Затем она конструирует HTML-ответ, используя шаблон строки, напрямую интерполируя переменную message в шаблон. Это может привести к XSS-уязвимости, если злоумышленник внедрит в параметр "name" вредоносные теги сценариев или другие HTML-сущности.

Чтобы решить эту проблему, вот пример совместимого кода, который правильно санирует пользовательский ввод для предотвращения XSS-атак:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
)

func handleHello(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	sanitized := template.HTMLEscapeString(name)
	message := fmt.Sprintf("Hello, %s!", sanitized)

	template := `<h1>Welcome</h1>
				 <p>%s</p>`

	output := fmt.Sprintf(template, message)
	fmt.Fprint(w, output)
}

func main() {
	http.HandleFunc("/hello", handleHello)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```


В коде, соответствующем требованиям, пакет html/template используется для санитарной обработки вводимых пользователем данных путем вызова функции template.HTMLEscapeString() для переменной name. Это гарантирует, что все специальные символы в пользовательском вводе будут правильно экранированы, предотвращая их интерпретацию как HTML-тегов или сущностей. Применяя правильное экранирование HTML, код устраняет XSS-уязвимость и предотвращает выполнение вредоносных скриптов в браузере пользователя.







## SQL-инъекция

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
)

func handleLogin(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	db, err := sql.Open("mysql", "root:password@/mydatabase")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	query := fmt.Sprintf("SELECT * FROM users WHERE username='%s' AND password='%s'", username, password)
	rows, err := db.Query(query)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	// Проверьте, был ли вход в систему успешным
	if rows.Next() {
		fmt.Fprintf(w, "Login successful")
	} else {
		fmt.Fprintf(w, "Login failed")
	}
}

func main() {
	http.HandleFunc("/login", handleLogin)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

В этом коде, не соответствующем требованиям, функция handleLogin обрабатывает маршрут "/login" и извлекает значения полей формы "имя пользователя" и "пароль" из HTTP-запроса. Затем она напрямую интерполирует эти значения в строку SQL-запроса без какой-либо проверки или санации ввода. Это делает код уязвимым для атак SQL-инъекций, в результате которых злоумышленник может манипулировать входными значениями, чтобы изменить предполагаемый запрос или выполнить произвольные SQL-запросы.

Чтобы решить эту проблему, приведем пример совместимого кода, в котором используются параметризованные запросы для предотвращения SQL-инъекций:




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"

	_ "github.com/go-sql-driver/mysql"
)

func handleLogin(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	db, err := sql.Open("mysql", "root:password@/mydatabase")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	query := "SELECT * FROM users WHERE username = ? AND password = ?"
	rows, err := db.Query(query, username, password)
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	// Проверьте, был ли вход в систему успешным
	if rows.Next() {
		fmt.Fprintf(w, "Login successful")
	} else {
		fmt.Fprintf(w, "Login failed")
	}
}

func main() {
	http.HandleFunc("/login", handleLogin)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

В соответствующем коде SQL-запрос модифицирован для использования параметризованных запросов. В строке запроса используются заполнители "?", а фактические значения передаются в качестве дополнительных аргументов в функцию db.Query. Это гарантирует, что введенные пользователем данные будут рассматриваться как данные, а не как часть структуры SQL-запроса, что эффективно предотвращает атаки SQL-инъекций. Благодаря использованию параметризованных запросов код отделяет логику SQL от данных и обеспечивает безопасный и надежный способ взаимодействия с базой данных.




## Внешнее управление именем или путем файла

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

func handleFileDownload(w http.ResponseWriter, r *http.Request) {
	fileName := r.URL.Query().Get("file")

	filePath := "/path/to/files/" + fileName

	file, err := os.Open(filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	fileContent, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", fileName))
	_, err = w.Write(fileContent)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	http.HandleFunc("/download", handleFileDownload)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```


В этом коде, не соответствующем требованиям, функция handleFileDownload обрабатывает маршрут "/download" и получает имя файла из параметров запроса. Затем она напрямую соединяет имя файла с базовым путем для построения пути к файлу. Это может привести к уязвимости безопасности, известной как "внешний контроль имени файла или пути", когда злоумышленник может манипулировать именем файла, чтобы получить доступ к файлам за пределами предполагаемого каталога или выполнить другие вредоносные действия.

Для решения этой проблемы приведен пример совместимого кода, который проверяет и санирует имя файла для предотвращения несанкционированного доступа к нему:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
)

func handleFileDownload(w http.ResponseWriter, r *http.Request) {
	fileName := r.URL.Query().Get("file")

	// Проверяем и дезинфицируем имя файла
	fileName = filepath.Clean(fileName)
	if fileName == "." || fileName == ".." {
		log.Fatal("Invalid file name")
	}

	filePath := "/path/to/files/" + fileName

	file, err := os.Open(filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	fileContent, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatal(err)
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", fileName))
	_, err = w.Write(fileContent)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	http.HandleFunc("/download", handleFileDownload)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

В соответствующем коде имя файла проверяется и обеззараживается с помощью функции filepath.Clean, которая удаляет любые элементы относительного пути (например, ".", ".") и преобразует имя файла к его канонической форме. Это гарантирует, что имя файла корректно, и предотвращает доступ к файлам за пределами предполагаемого каталога. Благодаря валидации и санации имени файла код снижает риск несанкционированного доступа к файлам и повышает безопасность функции загрузки файлов.






## Формирование сообщения об ошибке, содержащего конфиденциальную информацию

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
package main

import (
	"fmt"
	"log"
	"net/http"
)

func handleLogin(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Аутентификация пользователя
	if username == "admin" && password == "secretpassword" {
		// Успешный вход
		fmt.Fprintf(w, "Welcome, admin!")
	} else {
		// Неудачный вход
		errMsg := fmt.Sprintf("Login failed for user: %s", username)
		log.Println(errMsg)
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
	}
}

func main() {
	http.HandleFunc("/login", handleLogin)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```


В этом коде, не соответствующем требованиям, функция handleLogin обрабатывает маршрут "/login" и выполняет аутентификацию пользователя. Если вход не удается, код генерирует сообщение об ошибке, содержащее имя пользователя, и регистрирует его с помощью функции log.Println. Это может быть уязвимостью безопасности, поскольку в сообщении об ошибке раскрывается конфиденциальная информация (имя пользователя), которая может быть использована злоумышленником для разведки или социальной инженерии.

Чтобы решить эту проблему, вот пример совместимого кода, который позволяет избежать раскрытия конфиденциальной информации в сообщениях об ошибках:




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
package main

import (
	"fmt"
	"log"
	"net/http"
)

func handleLogin(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Аутентификация пользователя
	if username == "admin" && password == "secretpassword" {
		// Успешный вход
		fmt.Fprintf(w, "Welcome, admin!")
	} else {
		// Неудачный вход
		log.Println("Login failed for user:", username)
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
	}
}

func main() {
	http.HandleFunc("/login", handleLogin)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
```

В соответствующем коде сообщение об ошибке, регистрируемое с помощью log.Println, больше не содержит конфиденциальную информацию (имя пользователя). Вместо этого в журнал просто заносится общее сообщение о неудачном входе в систему без раскрытия какой-либо конфиденциальной информации. Избегая включения конфиденциальной информации в сообщения об ошибках, код снижает риск раскрытия конфиденциальной информации потенциальным злоумышленникам.





## Незащищенное хранение учетных данных

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
package main

import (
	"fmt"
	"log"
	"os"
)

var (
	username string
	password string
)

func readCredentials() {
	file, err := os.Open("credentials.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	fmt.Fscanf(file, "%s\n%s", &username, &password)
}

func main() {
	readCredentials()

	// Используйте учетные данные для аутентификации
	// ...
}
```

В этом коде, не соответствующем требованиям, функция readCredentials считывает имя пользователя и пароль из файла (credentials.txt). Однако файл считывается без каких-либо механизмов шифрования или защиты, что делает учетные данные уязвимыми для несанкционированного доступа. Хранение конфиденциальной информации в файлах с открытым текстом небезопасно и подвергает учетные данные опасности для потенциальных злоумышленников, получивших доступ к файлу.

Чтобы решить эту проблему, приведем пример совместимого кода, который защищает хранение учетных данных:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/crypto/bcrypt"
)

var (
	username string
	password []byte
)

func readCredentials() {
	file, err := os.Open(filepath.Join("secrets", "credentials.txt"))
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	fmt.Fscanf(file, "%s\n%s", &username, &password)
}

func authenticateUser(inputPassword []byte) bool {
	err := bcrypt.CompareHashAndPassword(password, inputPassword)
	if err != nil {
		return false
	}
	return true
}

func main() {
	readCredentials()

	// Получение данных пользователя для аутентификации
	// ...

	// Хеширование и сравнение паролей
	inputPassword := []byte("password123")
	if authenticateUser(inputPassword) {
		fmt.Println("Authentication successful!")
	} else {
		fmt.Println("Authentication failed!")
	}
}
```

В соответствующем коде было сделано несколько улучшений для улучшения хранения учетных данных:

1. Файл учетных данных хранится в отдельном каталоге с именем "secrets", чтобы ограничить доступ авторизованных пользователей.

2. Пароль надежно хранится с помощью алгоритма хэширования. В этом примере для хэширования и сравнения паролей используется пакет bcrypt. Это обеспечивает дополнительный уровень защиты от несанкционированного доступа к открытому тексту пароля.

Применяя эти меры безопасности, соответствующий код обеспечивает более надежное хранение учетных данных, снижая риск несанкционированного доступа к конфиденциальной информации.


## Нарушение границ доверия

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
package main

import (
	"fmt"
	"net/http"
	"os"
)

func fetchUserData(userID string) ([]byte, error) {
	url := fmt.Sprintf("https://api.example.com/users/%s", userID)
	response, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	// Прочитайте тело ответа
	data := make([]byte, response.ContentLength)
	_, err = response.Body.Read(data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func main() {
	userID := os.Args[1]
	userData, err := fetchUserData(userID)
	if err != nil {
		fmt.Printf("Error fetching user data: %s\n", err)
		return
	}

	fmt.Printf("User data: %s\n", userData)
}
```

В этом несоответствующем коде функция fetchUserData напрямую получает данные о пользователе из внешнего API (api.example.com) без проверки и санитарной обработки входных данных. Идентификатор пользователя берется в качестве аргументов командной строки и используется для построения URL-адреса API. Это приводит к нарушению границ доверия, поскольку код предполагает, что идентификатор пользователя является доверенным, и не выполняет никакой проверки ввода, что позволяет передавать потенциально вредоносный ввод и использовать его в URL.

Чтобы решить эту проблему, вот пример совместимого кода, в котором реализована проверка ввода и соблюдена граница доверия:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
$user_id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
package main

import (
	"fmt"
	"net/http"
	"os"
	"regexp"
)

func fetchUserData(userID string) ([]byte, error) {
	// Проверьте формат идентификатора пользователя
	validUserID := regexp.MustCompile(`^[a-zA-Z0-9]+$`)
	if !validUserID.MatchString(userID) {
		return nil, fmt.Errorf("Invalid user ID")
	}

	url := fmt.Sprintf("https://api.example.com/users/%s", userID)
	response, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	// Прочитайте тело ответа
	data := make([]byte, response.ContentLength)
	_, err = response.Body.Read(data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func main() {
	userID := os.Args[1]
	userData, err := fetchUserData(userID)
	if err != nil {
		fmt.Printf("Error fetching user data: %s\n", err)
		return
	}

	fmt.Printf("User data: %s\n", userData)
}
```


В совместимом коде было сделано несколько улучшений для решения проблемы нарушения границ доверия:

1. Идентификатор пользователя проверяется с помощью регулярного выражения, чтобы убедиться, что он соответствует ожидаемому формату (в данном случае только буквенно-цифровые символы). Это позволяет предотвратить использование произвольного ввода в URL-адресе API.

2. Если идентификатор пользователя не проходит проверку, возвращается ошибка, указывающая на то, что идентификатор пользователя недействителен.

Реализуя проверку ввода, соответствующий код обеспечивает границу доверия и гарантирует, что в вызове API будут использоваться только действительные и проверенные данные, что снижает риск того, что вредоносные данные приведут к неожиданному поведению или уязвимостям безопасности.




## Недостаточно защищенные учетные данные

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
package main

import (
	"fmt"
	"net/http"
	"os"
)

const (
	apiUsername = "admin"
	apiPassword = "password"
)

func fetchUserData(userID string) ([]byte, error) {
	url := fmt.Sprintf("https://api.example.com/users/%s", userID)
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.SetBasicAuth(apiUsername, apiPassword)

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	// Прочитайте тело ответа
	data := make([]byte, response.ContentLength)
	_, err = response.Body.Read(data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func main() {
	userID := os.Args[1]
	userData, err := fetchUserData(userID)
	if err != nil {
		fmt.Printf("Error fetching user data: %s\n", err)
		return
	}

	fmt.Printf("User data: %s\n", userData)
}
```

В этом несоответствующем коде учетные данные API (имя пользователя и пароль) жестко закодированы в исходном коде (константы apiUsername и apiPassword). Хранение учетных данных непосредственно в исходном коде представляет собой риск безопасности, поскольку если злоумышленник получит доступ к коду, он также будет иметь доступ к учетным данным.

Чтобы решить эту проблему, вот пример совместимого кода, который должным образом защищает учетные данные:




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
package main

import (
	"fmt"
	"net/http"
	"os"
)

func fetchUserData(userID string) ([]byte, error) {
	url := fmt.Sprintf("https://api.example.com/users/%s", userID)
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.SetBasicAuth(getAPIUsername(), getAPIPassword())

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	// Прочитайте тело ответа
	data := make([]byte, response.ContentLength)
	_, err = response.Body.Read(data)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func getAPIUsername() string {
	// Получите имя пользователя API из безопасной конфигурации или переменной окружения
	return "admin"
}

func getAPIPassword() string {
	// Получите пароль API из безопасной конфигурации или переменной окружения
	return "password"
}

func main() {
	userID := os.Args[1]
	userData, err := fetchUserData(userID)
	if err != nil {
		fmt.Printf("Error fetching user data: %s\n", err)
		return
	}

	fmt.Printf("User data: %s\n", userData)
}
```


В совместимом коде учетные данные больше не хранятся в исходном коде в жестком виде. Вместо этого функции getAPIUsername и getAPIPassword получают учетные данные из защищенных конфигураций или переменных среды. Такое отделение конфиденциальной информации от кода помогает защитить учетные данные и снижает риск их раскрытия в случае компрометации кода.

Благодаря надлежащей защите учетных данных и обеспечению их получения из безопасных источников, соответствующий код снижает риск несанкционированного доступа к конфиденциальной информации.






## Ограничение ссылки на внешние сущности XML

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
package main

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

type User struct {
	ID   int    `xml:"id"`
	Name string `xml:"name"`
}

func getUserData(userID string) (*User, error) {
	url := fmt.Sprintf("https://api.example.com/users/%s", userID)
	response, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	user := &User{}
	err = xml.Unmarshal(data, user)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func main() {
	userID := os.Args[1]
	user, err := getUserData(userID)
	if err != nil {
		fmt.Printf("Error retrieving user data: %s\n", err)
		return
	}

	fmt.Printf("User ID: %d, Name: %s\n", user.ID, user.Name)
}
```

В этом несовместимом коде XML-данные, полученные от API (response.Body), напрямую считываются и разбираются с помощью функции xml.Unmarshal. Однако явного ограничения или защиты от ссылок на внешние сущности XML (XXE) не существует. Это делает код уязвимым для XXE-атак, когда злоумышленник может предоставить вредоносный XML-контент, содержащий ссылки на внешние сущности, для раскрытия конфиденциальной информации или выполнения других несанкционированных действий.

Чтобы решить эту проблему, приведем пример совместимого кода, который должным образом ограничивает ссылки на внешние сущности XML:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
package main

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

type User struct {
	ID   int    `xml:"id"`
	Name string `xml:"name"`
}

func getUserData(userID string) (*User, error) {
	url := fmt.Sprintf("https://api.example.com/users/%s", userID)
	response, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	decoder := xml.NewDecoder(response.Body)
	decoder.Strict = true  // Включите строгий разбор XML
	decoder.Entity = xml.HTMLEntity // Отключите расширение внешних сущностей

	user := &User{}
	err = decoder.Decode(user)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func main() {
	userID := os.Args[1]
	user, err := getUserData(userID)
	if err != nil {
		fmt.Printf("Error retrieving user data: %s\n", err)
		return
	}

	fmt.Printf("User ID: %d, Name: %s\n", user.ID, user.Name)
}
```


В соответствующем коде мы используем xml.Decoder для строгого разбора XML и ограничения расширения внешних сущностей. Мы устанавливаем для поля Strict декодера значение true, а для поля Entity - xml.HTMLEntity, чтобы запретить расширение внешних сущностей.

Обеспечивая строгий разбор XML и запрещая расширение внешних сущностей, соответствующий код эффективно снижает риск атак на внешние сущности XML (XXE) и гарантирует, что обрабатывается только безопасный XML-контент.





## Уязвимые и устаревшие компоненты


<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
package main

import (
	"fmt"
	"github.com/vulnerable/library"
)

func main() {
	data := "Sensitive information"
	encryptedData := library.OldEncryption(data) // Using a vulnerable and outdated encryption function

	fmt.Println("Encrypted Data:", encryptedData)
}
```

В этом несоответствующем коде мы импортируем уязвимую и устаревшую библиотеку (github.com/vulnerable/library) и используем ее функцию OldEncryption для шифрования конфиденциальной информации. Устаревшая функция шифрования может иметь известные уязвимости или слабые места, которые могут быть использованы злоумышленниками.

Чтобы решить эту проблему, вот пример совместимого кода, который позволяет избежать использования уязвимых и устаревших компонентов:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
package main

import (
	"fmt"
	"github.com/secure/library"
)

func main() {
	data := "Sensitive information"
	encryptedData := library.NewEncryption(data) // Использование надежной и обновленной функции шифрования

	fmt.Println("Encrypted Data:", encryptedData)
}
```


В соответствующем коде мы импортируем безопасную и обновленную библиотеку (github.com/secure/library), которая предоставляет функцию NewEncryption для шифрования конфиденциальной информации. Новая функция шифрования включает в себя новейшие методы обеспечения безопасности и устраняет все известные уязвимости, присутствующие в старой функции шифрования.

Благодаря использованию безопасных и обновленных компонентов соответствующий код снижает риск потенциальных уязвимостей и обеспечивает надлежащую защиту конфиденциальной информации при шифровании. Важно регулярно обновлять и проверять компоненты, используемые в приложении, чтобы убедиться, что они не содержат известных уязвимостей и обновлены последними исправлениями безопасности.






## Неправильная проверка сертификата с несоответствием хоста

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
)

func main() {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Отключает проверку сертификатов
		},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()

	// Обработать ответ
	// ...
}
```

В этом несоответствующем коде поле InsecureSkipVerify установлено в true, что отключает проверку сертификата. Это означает, что клиент примет любой сертификат, даже если он не соответствует ожидаемому хосту (в данном случае example.com). Это может привести к потенциальной уязвимости безопасности, так как позволяет осуществлять атаки типа "человек посередине" и подвергает приложение риску взаимодействия с неавторизованным или вредоносным сервером.

Чтобы решить эту проблему, приведем пример соответствующего кода, который правильно проверяет сертификат на соответствие ожидаемому хосту:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
)

func main() {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false, // Включает проверку сертификата
		},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get("https://example.com")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	defer resp.Body.Close()

	// Обработка ответа
	// ...
}
```


В соответствующем коде для поля InsecureSkipVerify установлено значение false, что включает проверку сертификата. Это гарантирует, что клиент проверит сертификат сервера и убедится, что он соответствует ожидаемому хосту (example.com). Благодаря правильной проверке сертификата соответствующий код снижает риск взаимодействия с неавторизованными или вредоносными серверами и защищает целостность и конфиденциальность связи.






## Неправильная аутентификация

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/dashboard", dashboardHandler)
	http.ListenAndServe(":8080", nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Выполните аутентификацию
	if username == "admin" && password == "password" {
		// Успешная аутентификация
		// ...
		fmt.Fprintf(w, "Login successful!")
	} else {
		// Неудачная аутентификация
		// ...
		fmt.Fprintf(w, "Login failed!")
	}
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	// Проверьте, прошел ли пользователь аутентификацию
	if isAuthenticated(r) {
		// Показать приборную панель
		// ...
		fmt.Fprintf(w, "Welcome to the dashboard!")
	} else {
		// Перенаправление на страницу входа в систему
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func isAuthenticated(r *http.Request) bool {
	// Проверьте, аутентифицирован ли пользователь.
	// ...
	return false
}
```

В этом несоответствующем коде механизм аутентификации реализован с помощью простого сравнения имени пользователя и пароля в функции loginHandler. Учетные данные отправляются открытым текстом, и для защиты конфиденциальной информации не применяются дополнительные меры безопасности, такие как шифрование или хеширование. Кроме того, состояние аутентификации не поддерживается должным образом, и любой пользователь может получить доступ к приборной панели без аутентификации, напрямую посетив URL /dashboard.

Чтобы решить эти проблемы, вот пример совместимого кода, который демонстрирует правильную аутентификацию в Go:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
package main

import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"net/http"
)

func main() {
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/dashboard", dashboardHandler)
	http.ListenAndServe(":8080", nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Получение сохраненного хэшированного пароля для данного имени пользователя
	hashedPassword, _ := getHashedPassword(username)

	// Сравните введенный пароль с хэшированным паролем
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err == nil {
		// Успешная аутентификация
		// ...
		fmt.Fprintf(w, "Login successful!")
	} else {
		// Неудачная аутентификация
		// ...
		fmt.Fprintf(w, "Login failed!")
	}
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	// Проверьте, прошел ли пользователь аутентификацию
	if isAuthenticated(r) {
		// Показать дашборд
		// ...
		fmt.Fprintf(w, "Welcome to the dashboard!")
	} else {
		// Перенаправление на страницу входа в систему
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func isAuthenticated(r *http.Request) bool {
	// Проверьте, аутентифицирован ли пользователь.
	// ...
	return false
}

func getHashedPassword(username string) (string, error) {
	// Извлеките из хранилища хэшированный пароль для заданного имени пользователя
	// ...
	return "", nil
}
```


В соответствующем коде пароли надежно хранятся в виде хэшированных значений с помощью алгоритма хэширования bcrypt. В процессе входа в систему предоставленный пароль хэшируется и сравнивается с сохраненным хэшированным паролем с помощью bcrypt.CompareHashAndPassword. Это гарантирует, что пароли не будут храниться или передаваться открытым текстом, обеспечивая дополнительный уровень безопасности. Кроме того, состояние аутентификации поддерживается должным образом, и несанкционированный доступ к приборной панели






## Фиксация сеанса

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
package main

import (
	"fmt"
	"net/http"
)

var sessionID string

func main() {
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/dashboard", dashboardHandler)
	http.ListenAndServe(":8080", nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")

	// Выполните аутентификацию
	if username == "admin" {
		// Успешная аутентификация
		sessionID = "123456" // Fixed session ID
		http.SetCookie(w, &http.Cookie{Name: "sessionID", Value: sessionID})
		fmt.Fprintf(w, "Login successful!")
	} else {
		// Неудачная аутентификация
		fmt.Fprintf(w, "Login failed!")
	}
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	// Проверьте, есть ли у пользователя действительная сессия
	if r.Cookie != nil && r.Cookie["sessionID"] != nil && r.Cookie["sessionID"].Value == sessionID {
		// Показать дашборд
		fmt.Fprintf(w, "Welcome to the dashboard!")
	} else {
		// Перенаправление на страницу входа в систему
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}
```

В этом несоответствующем коде присутствует уязвимость фиксации сеанса. Переменная sessionID - это глобальная переменная, которая хранит идентификатор сессии после успешной аутентификации. Затем идентификатор сессии устанавливается в качестве значения cookie с помощью http.SetCookie. Однако идентификатор сессии фиксирован и не меняется между различными пользовательскими сессиями. Это позволяет злоумышленнику зафиксировать свой собственный идентификатор сессии и потенциально перехватить сессию легитимного пользователя.

Чтобы устранить эту уязвимость, вот пример совместимого кода, который устраняет уязвимость фиксации сеанса в Go:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/dashboard", dashboardHandler)
	http.ListenAndServe(":8080", nil)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")

	// Выполните аутентификацию
	if username == "admin" {
		// Генерируем новый идентификатор сессии
		sessionID := generateSessionID()

		// Установите идентификатор сессии в качестве значения cookie
		http.SetCookie(w, &http.Cookie{Name: "sessionID", Value: sessionID})

		// Перенаправление на дашборд
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	} else {
		// Неудачная аутентификация
		fmt.Fprintf(w, "Login failed!")
	}
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	// Проверьте, есть ли у пользователя действительная сессия
	sessionIDCookie, err := r.Cookie("sessionID")
	if err == nil && isValidSessionID(sessionIDCookie.Value) {
		// Показать дашборд
		fmt.Fprintf(w, "Welcome to the dashboard!")
	} else {
		// Перенаправление на страницу входа в систему
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

func generateSessionID() string {
	// Создайте новый идентификатор сессии
	// ...
	return "generated-session-id"
}

func isValidSessionID(sessionID string) bool {
	// Проверьте, действителен ли идентификатор сессии.
	// ...
	return true
}
```


В соответствующем коде идентификатор сессии больше не хранится в глобальной переменной, а генерируется динамически с помощью функции generateSessionID. После успешной аутентификации генерируется новый идентификатор сессии и устанавливается в качестве значения cookie с помощью http.SetCookie. После этого пользователь перенаправляется на страницу дашборда.




## Включение функциональности из недоверенного управления

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
package main

import (
	"fmt"
	"net/http"
	"os/exec"
)

func main() {
	http.HandleFunc("/execute", executeHandler)
	http.ListenAndServe(":8080", nil)
}

func executeHandler(w http.ResponseWriter, r *http.Request) {
	command := r.FormValue("command")

	// Выполните команду, полученную от пользователя
	output, err := exec.Command(command).CombinedOutput()
	if err != nil {
		fmt.Fprintf(w, "Error executing command: %v", err)
		return
	}

	fmt.Fprintf(w, "Command output:\n%s", output)
}
```

В этом несоответствующем коде функция executeHandler получает команду от пользователя в качестве параметра запроса (command). Код напрямую выполняет полученную команду, используя exec.Command, без какой-либо проверки или санации вводимых команд. Это создает значительный риск безопасности, поскольку позволяет злоумышленнику выполнять произвольные команды на базовой системе, что может привести к удаленному выполнению кода и несанкционированному доступу.

Чтобы устранить этот риск безопасности, приведем пример соответствующего кода, который снижает вероятность включения в Go функциональности из ненадежного управления:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
package main

import (
	"fmt"
	"net/http"
	"os/exec"
	"strings"
)

func main() {
	http.HandleFunc("/execute", executeHandler)
	http.ListenAndServe(":8080", nil)
}

func executeHandler(w http.ResponseWriter, r *http.Request) {
	command := r.FormValue("command")

	// Проверяем и обеззараживаем вводимые команды
	if !isValidCommand(command) {
		fmt.Fprintf(w, "Invalid command")
		return
	}

	// Выполните подтвержденную команду
	output, err := exec.Command(command).CombinedOutput()
	if err != nil {
		fmt.Fprintf(w, "Error executing command: %v", err)
		return
	}

	fmt.Fprintf(w, "Command output:\n%s", output)
}

func isValidCommand(command string) bool {
	// Проверяем вводимые команды на соответствие белому списку разрешенных команд
	allowedCommands := []string{"ls", "echo", "pwd"} // Example whitelist

	for _, allowedCmd := range allowedCommands {
		if command == allowedCmd {
			return true
		}
	}

	return false
}
```


В соответствующем коде функция executeHandler проверяет и обеззараживает входные данные команды, полученные от пользователя. Она проверяет команду на соответствие белому списку разрешенных команд (allowedCommands). Только те команды, которые присутствуют в белом списке, считаются допустимыми и будут выполнены. Любая команда, не присутствующая в белом списке, отклоняется, предотвращая выполнение произвольных команд. Это позволяет снизить риск включения функциональности из ненадежных систем управления.




## Загрузка кода без проверки целостности

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

func main() {
	url := "http://example.com/malicious-code.zip"
	filePath := "/path/to/save/malicious-code.zip"

	// Загрузите файл с указанного URL
	response, err := http.Get(url)
	if err != nil {
		fmt.Println("Error downloading file:", err)
		return
	}
	defer response.Body.Close()

	// Прочитайте содержимое тела ответа
	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}

	// Сохраните загруженный файл
	err = ioutil.WriteFile(filePath, data, 0644)
	if err != nil {
		fmt.Println("Error saving file:", err)
		return
	}

	fmt.Println("File downloaded successfully!")
}
```

В этом несоответствующем коде программа загружает файл с указанного URL с помощью функции http.Get и сохраняет его в локальном файле с помощью ioutil.WriteFile. Однако код не выполняет никакой проверки целостности загруженного файла. Это делает систему уязвимой для потенциальных атак, таких как загрузка и выполнение вредоносного кода или подделка загруженного файла.

Чтобы устранить этот риск безопасности, вот пример совместимого кода, который включает проверку целостности при загрузке кода в Go:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

func main() {
	url := "http://example.com/malicious-code.zip"
	filePath := "/path/to/save/malicious-code.zip"

	// Загрузите файл с указанного URL
	response, err := http.Get(url)
	if err != nil {
		fmt.Println("Error downloading file:", err)
		return
	}
	defer response.Body.Close()

	// Прочитайте содержимое тела ответа
	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}

	// Выполните проверку целостности загруженного файла
	if !isFileIntegrityValid(data) {
		fmt.Println("File integrity check failed!")
		return
	}

	// Сохраните загруженный файл
	err = ioutil.WriteFile(filePath, data, 0644)
	if err != nil {
		fmt.Println("Error saving file:", err)
		return
	}

	fmt.Println("File downloaded and saved successfully!")
}

func isFileIntegrityValid(data []byte) bool {
	// Реализуйте алгоритм проверки целостности (например, криптографический хэш)
	// для проверки целостности загруженного файла
	// и возвращает true, если проверка целостности пройдена, или false в противном случае

	// Пример с использованием хэша SHA256
	expectedHash := "..."
	actualHash := calculateHash(data)

	return expectedHash == actualHash
}

func calculateHash(data []byte) string {
	// Вычислите хэш данных с помощью подходящей криптографической хэш-функции
	// и возвращаем хэш-значение в виде строки

	// Пример с использованием хэша SHA256
	// ...

	return "..."
}
```


В соответствующем коде после чтения содержимого тела ответа выполняется проверка целостности загруженного файла с помощью функции isFileIntegrityValid. Функция реализует алгоритм проверки целостности, например вычисление криптографического хэша (например, SHA256) данных файла. Если проверка целостности пройдена, файл сохраняется в локальном пути. В противном случае код отвергает файл и завершает процесс. 





## Десериализация недоверенных данных

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
package main

import (
	"encoding/json"
	"fmt"
	"log"
)

type User struct {
	ID       int
	Username string
	Email    string
}

func main() {
	data := `{"ID": 1, "Username": "john", "Email": "john@example.com"}`

	var user User
	err := json.Unmarshal([]byte(data), &user)
	if err != nil {
		log.Fatal("Error deserializing user:", err)
	}

	fmt.Println("User:", user)
}
```

В этом коде, не соответствующем требованиям, программа десериализует строку JSON, представляющую пользовательский объект, с помощью json.Unmarshal. Однако она не выполняет никакой проверки или санации входных данных. Это делает систему уязвимой для потенциальных атак, таких как десериализация злонамеренно созданных данных, что может привести к выполнению кода, раскрытию информации или другим рискам безопасности.

Чтобы устранить этот риск безопасности, вот пример соответствующего кода, который включает в себя надлежащую проверку и санацию при десериализации недоверенных данных в Go:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
package main

import (
	"encoding/json"
	"fmt"
	"log"
)

type User struct {
	ID       int
	Username string
	Email    string
}

func main() {
	data := `{"ID": 1, "Username": "john", "Email": "john@example.com"}`

	// Выполните проверку и санацию ввода
	if !isValidJSON(data) {
		log.Fatal("Invalid JSON data")
	}

	var user User
	err := json.Unmarshal([]byte(data), &user)
	if err != nil {
		log.Fatal("Error deserializing user:", err)
	}

	// Выполните дополнительную проверку десериализованного объекта пользователя
	if !isValidUser(user) {
		log.Fatal("Invalid user data")
	}

	fmt.Println("User:", user)
}

func isValidJSON(data string) bool {
	// Реализуйте логику проверки, чтобы убедиться, что входные данные являются корректным JSON
	// и возвращать true, если данные валидны, или false в противном случае.

	// Пример: использование функции json.Valid из пакета encoding/json
	return json.Valid([]byte(data))
}

func isValidUser(user User) bool {
	// Реализуйте дополнительную логику проверки десериализованного объекта пользователя
	// чтобы убедиться, что он соответствует требованиям приложения
	// и возвращать true, если он валиден, или false в противном случае

	// Пример: проверка соответствия имени пользователя и электронной почты определенным критериям
	if len(user.Username) < 3 || len(user.Email) == 0 {
		return false
	}

	return true
}
```


В соответствующем коде перед десериализацией JSON-данных входные данные сначала проверяются с помощью функции isValidJSON, чтобы убедиться, что это корректный JSON. Если данные не являются валидными, процесс завершается. После десериализации выполняется дополнительная проверка десериализованного объекта User с помощью функции isValidUser, чтобы убедиться, что он соответствует требованиям приложения. Если данные пользователя считаются недействительными, процесс завершается.


Благодаря включению шагов проверки и санации, соответствующий код снижает риск десериализации недоверенных данных и помогает предотвратить потенциальные уязвимости безопасности, связанные с атаками на десериализацию.





## Недостаточное ведение журнала

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	http.HandleFunc("/", handleRequest)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	// Обработка запроса
	// ...

	// Зафиксируйте данные запроса
	log.Println("Получен запрос:", r.Method, r.URL.Path)

	// Выполните конфиденциальную операцию
	performSensitiveOperation()

	// Зафиксируйте завершение запроса
	log.Println("Запрос успешно обработан")
}

func performSensitiveOperation() {
	// Выполняем чувствительную операцию
	// ...

	// Запись в журнал о выполнении чувствительной операции
	log.Println("Выполнена чувствительная операция")
}
```

В этом несоответствующем коде протоколирование используется для фиксации деталей запроса и выполнения конфиденциальной операции. Однако протоколирование ограничивается использованием стандартного логгера из пакета log, который обычно ведет журнал в стандартный вывод ошибок или предопределенный файл журнала. Такой подход недостаточен для эффективного протоколирования, поскольку в нем отсутствует важная информация, такая как уровни журнала, временные метки и контекстные детали.

Чтобы решить эту проблему и обеспечить достаточное протоколирование, ниже приведен пример совместимого кода, в котором реализовано более надежное решение для протоколирования с помощью специального пакета протоколирования, например logrus:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
package main

import (
	"fmt"
	"net/http"
	"os"

	log "github.com/sirupsen/logrus"
)

func main() {
	// Инициализация регистратора
	initLogger()

	http.HandleFunc("/", handleRequest)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func initLogger() {
	// Установите нужный вывод журнала, формат и уровень
	log.SetOutput(os.Stdout)
	log.SetFormatter(&log.JSONFormatter{})
	log.SetLevel(log.InfoLevel)
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	// Обработка запроса
	// ...

	// Зафиксируйте детали запроса
	log.WithFields(log.Fields{
		"method": r.Method,
		"path":   r.URL.Path,
	}).Info("Request received")

	// Выполните некоторую чувствительную операцию
	performSensitiveOperation()

	// Зафиксируйте завершение запроса
	log.Info("Запрос успешно обработан")
}

func performSensitiveOperation() {
	// Выполняем чувствительную операцию
	// ...

	// Запись в журнал о выполнении чувствительной операции
	log.Warn("Выполнена чувствительная операция")
}
```


В соответствующем коде для ведения журнала используется пакет logrus. Ведение журнала инициализируется в функции initLogger, где задается желаемый вывод журнала, формат и уровень. В данном примере логи направляются на стандартный вывод, форматируются как JSON, а уровень лога установлен на InfoLevel.

Функция handleRequest демонстрирует, как заносить в журнал данные о запросе и выполнении конфиденциальной операции с помощью методов log.Info и log.Warn соответственно. В журналы включается дополнительная контекстная информация с помощью метода WithFields для создания структурированной записи журнала.

При использовании более функционального пакета протоколирования, такого как logrus, код, соответствующий требованиям, расширяет возможности протоколирования, предоставляя уровни журналов, временные метки и контекстную информацию. Это позволяет улучшить поиск и устранение неисправностей, мониторинг и анализ безопасности.




## Неправильная нейтрализация выхода для бревен

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/", handleRequest)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")

	// Введите имя пользователя
	log.Println("User logged in:", username)

	// Обработка запроса
	// ...
}
```

В этом коде, не соответствующем требованиям, имя пользователя, полученное в результате запроса, напрямую записывается в журнал с помощью функции log.Println. Такая практика небезопасна, поскольку может привести к атакам с внедрением в журнал или непреднамеренному раскрытию конфиденциальной информации. Злоумышленник может воспользоваться этой уязвимостью, вставив в имя пользователя специальные символы или новые строки, чтобы изменить вывод журнала или нарушить структуру файла журнала.

Чтобы решить эту проблему и обеспечить надлежащую нейтрализацию вывода журналов, вот пример соответствующего кода, который включает санирование вывода с помощью функции log.Printf:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
)

func main() {
	http.HandleFunc("/", handleRequest)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")

	// Дезинфекция имени пользователя
	sanitizedUsername := sanitizeString(username)

	// Выводим в журнал санированное имя пользователя
	log.Printf("Пользователь вошел в систему: %s", sanitizedUsername)

	// Обрабатываем запрос
	// ...
}

func sanitizeString(s string) string {
	// Замените специальные символы, которые могут повлиять на вывод журнала
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\t", "\\t")

	return s
}
```


В соответствующем коде появилась функция sanitizeString, которая обеззараживает имя пользователя перед записью в журнал. Она заменяет специальные символы, такие как новая строка (\n), возврат каретки (\r) и табуляция (\t), на экранирующие последовательности, чтобы предотвратить их непреднамеренную интерпретацию или влияние на вывод журнала.

Продезинфицированное имя пользователя затем записывается в журнал с помощью log.Printf с соответствующим спецификатором формата %s. Это гарантирует, что запись в журнале будет правильно нейтрализована и не внесет никаких уязвимостей или непреднамеренного поведения.

Дезинфекция вывода журнала таким образом позволяет совместимому коду снизить риск инъекционных атак на журнал и обеспечить надлежащую защиту конфиденциальной информации в файлах журнала.






## Упущение информации, имеющей отношение к безопасности

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/", handleRequest)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Зарегистрируйте событие входа пользователя в систему
	log.Printf("User logged in: %s", username)

	// Обработка запроса
	// ...
}
```


В этом коде, не соответствующем требованиям, при входе пользователя в систему регистрируется только имя пользователя. Однако пароль, который является важной для безопасности информацией, не включается в запись журнала. Отсутствие такой важной для безопасности информации может помешать эффективному мониторингу и расследованию инцидентов безопасности.

Чтобы решить эту проблему и обеспечить включение в журналы информации, имеющей отношение к безопасности, вот пример соответствующего кода, который включает всю необходимую информацию в журнал:




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/", handleRequest)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Зафиксируйте событие входа пользователя в систему со всей необходимой информацией
	log.Printf("User logged in - Username: %s, Password: %s", username, password)

	// Обработка запроса
	// ...
}
```


В коде, соответствующем требованиям, имя пользователя и пароль включаются в запись журнала с помощью функции log.Printf. Включая всю необходимую информацию о безопасности, такую как имя пользователя и пароль, в запись журнала, код, соответствующий требованиям, предоставляет ценную информацию для мониторинга, аудита и расследования инцидентов безопасности.

Важно отметить, что, хотя записывать в журнал такую конфиденциальную информацию, как пароли, обычно не рекомендуется, этот пример приведен для того, чтобы рассмотреть проблему отсутствия в журналах информации, имеющей отношение к безопасности. В реальном сценарии рекомендуется избегать регистрации конфиденциальной информации и использовать такие методы, как токенизация или обфускация, для защиты конфиденциальных данных.







## Помещение конфиденциальной информации в файл журнала

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	http.HandleFunc("/", handleRequest)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Зафиксируйте конфиденциальную информацию
	logFile, err := os.OpenFile("app.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer logFile.Close()

	logger := log.New(logFile, "", log.LstdFlags)
	logger.Printf("Sensitive information - Username: %s, Password: %s", username, password)

	// Обработка запроса
	// ...
}
```

В этом несоответствующем коде конфиденциальная информация, включая имя пользователя и пароль, записывается непосредственно в файл журнала с помощью функции log.Printf. Хранение конфиденциальной информации в лог-файлах в виде обычного текста может создать угрозу безопасности, так как к лог-файлам могут получить доступ неавторизованные лица, что приведет к раскрытию конфиденциальных данных.

Чтобы решить эту проблему и предотвратить хранение конфиденциальной информации в файле журнала, ниже приведен пример соответствующего кода:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/", handleRequest)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Обработка запроса

	// Зарегистрируйте сообщение, не содержащее конфиденциальной информации
	log.Printf("Received request - Username: %s", username)

	// Выполните аутентификацию
	if !authenticate(username, password) {
		log.Printf("Authentication failed for user: %s", username)
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	// Продолжаем запрос
	// ...
}

func authenticate(username, password string) bool {
	// Выполните логику аутентификации
	// ...
}
```


В соответствующем коде конфиденциальная информация не записывается непосредственно в файл журнала. Вместо этого код регистрирует сообщение о полученном запросе, не включая фактическую конфиденциальную информацию. Избегая регистрации конфиденциальных данных, соответствующий код обеспечивает защиту конфиденциальной информации и снижает риск несанкционированного доступа или воздействия.

Важно следовать лучшим практикам работы с конфиденциальной информацией, например не хранить ее в лог-файлах, шифровать ее при необходимости и соблюдать соответствующие правила защиты данных и рекомендации по безопасности.





## Подделка запросов со стороны сервера (SSRF)

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```php
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/fetch", handleFetch)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleFetch(w http.ResponseWriter, r *http.Request) {
	url := r.FormValue("url")

	// Выполните запрос на указанный URL
	response, err := http.Get(url)
	if err != nil {
		log.Fatal(err)
	}

	defer response.Body.Close()

	// Прочитайте тело ответа
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Fprintf(w, "Response Body: %s", body)
}
```

В этом несоответствующем коде функция handleFetch позволяет пользователю указать URL через параметр url. Затем код выполняет запрос к указанному URL без выполнения какой-либо проверки или ограничения. Это может привести к уязвимости SSRF, когда злоумышленник потенциально может заставить сервер выполнять непредусмотренные запросы к внутренним ресурсам или внешним системам.

Чтобы решить эту проблему и предотвратить SSRF-атаки, вот пример соответствующего кода:






<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```php
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
)

func main() {
	http.HandleFunc("/fetch", handleFetch)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleFetch(w http.ResponseWriter, r *http.Request) {
	rawURL := r.FormValue("url")

	// Разберите URL, чтобы убедиться, что он действителен и безопасен.
	parsedURL, err := url.ParseRequestURI(rawURL)
	if err != nil {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}

	// Убедитесь, что URL указывает на разрешенный домен
	allowedDomains := []string{"example.com", "trusteddomain.com"}
	if !isDomainAllowed(parsedURL.Host, allowedDomains) {
		http.Error(w, "Access to the specified domain is not allowed", http.StatusForbidden)
		return
	}

	// Выполните запрос на указанный URL
	response, err := http.Get(parsedURL.String())
	if err != nil {
		log.Fatal(err)
	}

	defer response.Body.Close()

	// Прочитайте тело ответа
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Fprintf(w, "Response Body: %s", body)
}

func isDomainAllowed(domain string, allowedDomains []string) bool {
	for _, allowedDomain := range allowedDomains {
		if domain == allowedDomain {
			return true
		}
	}
	return false
}
```


В соответствующем коде предпринято несколько мер по снижению уязвимости SSRF:

1. Функция url.ParseRequestURI используется для разбора и проверки предоставленного URL. Это гарантирует, что URL хорошо сформирован и соответствует ожидаемому формату.
2. Определяется список разрешенных доменов, а функция isDomainAllowed используется для проверки наличия хоста разобранного URL в списке разрешенных доменов. Это ограничивает запросы только указанными доменами, предотвращая атаки SSRF.
3. Реализована корректная обработка ошибок для возврата соответствующих HTTP-ответов на недействительные URL или попытки несанкционированного доступа.

Проверяя и ограничивая URL-адреса, которые могут быть запрошены, соответствующий код помогает предотвратить несанкционированный или злонамеренный доступ к внутренним или внешним ресурсам, тем самым снижая уязвимость SSRF.
