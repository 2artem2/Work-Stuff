---
layout: default
title: Swift
parent: Rules
---

# Swift
{: .no_toc }


## Оглавление
{: .no_toc .text-delta }

1. TOC
{:toc}

---






### Неправильное использование платформы

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```java
import UIKit

class ViewController: UIViewController {
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        let urlString = "http://example.com/api/data"
        let url = URL(string: urlString)!
        let request = URLRequest(url: url)
        
        let task = URLSession.shared.dataTask(with: request) { (data, response, error) in
            if let error = error {
                print("Error: \(error.localizedDescription)")
                return
            }
            
            if let data = data {
                let json = try? JSONSerialization.jsonObject(with: data, options: [])
                print("Response: \(json ?? "")")
            }
        }
        
        task.resume()
    }
}
```

Несоответствующий требованиям код выполняет HTTP-запрос к удаленному URL с помощью URLSession.shared.dataTask(with:completionHandler:) без надлежащей проверки или обработки потенциальных проблем безопасности. Он не проверяет, является ли удаленный URL безопасным (HTTPS) или принадлежит ли он к доверенному домену. Это может привести к уязвимостям безопасности, таким как атаки типа "человек посередине" или подключение к вредоносным серверам.

Чтобы решить эту проблему, приведем пример совместимого кода:




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```java
import UIKit

class ViewController: UIViewController {
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        let urlString = "https://example.com/api/data"
        
        guard let urlComponents = URLComponents(string: urlString),
              let host = urlComponents.host,
              let scheme = urlComponents.scheme,
              scheme.lowercased().hasPrefix("https") else {
            print("Invalid URL or scheme")
            return
        }
        
        // При необходимости выполните дополнительные проверки, например, проверьте домен или сертификат.
        
        guard let url = urlComponents.url else {
            print("Failed to create URL")
            return
        }
        
        let request = URLRequest(url: url)
        
        let task = URLSession.shared.dataTask(with: request) { (data, response, error) in
            if let error = error {
                print("Error: \(error.localizedDescription)")
                return
            }
            
            if let data = data {
                let json = try? JSONSerialization.jsonObject(with: data, options: [])
                print("Response: \(json ?? "")")
            }
        }
        
        task.resume()
    }
}
```


Соответствующий код решает проблему неправильного использования платформы, выполняя дополнительные проверки URL. Он использует URLComponents для разбора и извлечения хоста и схемы из URL. Затем он проверяет, что схема является HTTPS, прежде чем продолжить выполнение запроса. При необходимости можно добавить дополнительные проверки, например, проверку домена или сертификата перед выполнением запроса. Убедившись, что URL-адрес безопасен и надежен, код снижает потенциальные риски безопасности, связанные с неправильным использованием платформы.





### Небезопасное хранение данных

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```java
import UIKit

class ViewController: UIViewController {
    
    let password = "myPassword"
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // Сохранение пароля в UserDefaults
        UserDefaults.standard.set(password, forKey: "password")
        
        // Чтение пароля из UserDefaults
        let storedPassword = UserDefaults.standard.string(forKey: "password")
        print("Stored Password: \(storedPassword ?? "")")
    }
}
```

Код, не соответствующий требованиям, хранит конфиденциальную строку пароля непосредственно в UserDefaults, что небезопасно. UserDefaults не предназначен для безопасного хранения данных и не должен использоваться для хранения конфиденциальной информации, такой как пароли или маркеры аутентификации. Хранение конфиденциальных данных в UserDefaults может подвергнуть их потенциальным рискам безопасности, включая несанкционированный доступ или извлечение злоумышленниками.

Чтобы решить эту проблему, вот пример совместимого кода:







<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```java
import UIKit
import KeychainAccess

class ViewController: UIViewController {
    
    let password = "myPassword"
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        do {
            // Сохранение пароля в связке ключей
            let keychain = Keychain(service: "com.example.app")
            try keychain.set(password, key: "password")
            
            // Чтение пароля из связки ключей
            let storedPassword = try keychain.get("password")
            print("Stored Password: \(storedPassword ?? "")")
        } catch {
            print("Error: \(error.localizedDescription)")
        }
    }
}
```


Соответствующий код решает проблему небезопасного хранения данных, используя безопасный механизм хранения, в данном случае библиотеку KeychainAccess. Секретный пароль хранится в связке ключей, которая обеспечивает более безопасное хранение по сравнению с UserDefaults. Keychain предназначен для безопасного хранения конфиденциальной информации, такой как пароли или криптографические ключи, и предлагает дополнительные меры защиты, такие как шифрование и контроль доступа, чтобы обеспечить конфиденциальность и целостность хранимых данных. Используя связку ключей для хранения конфиденциальных данных, код снижает потенциальные риски безопасности, связанные с использованием небезопасных хранилищ данных.




### Небезопасная связь

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```java
import UIKit

class ViewController: UIViewController {
    
    let apiUrl = "http://example.com/api"
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // Небезопасная отправка запроса к API
        if let url = URL(string: apiUrl) {
            let request = URLRequest(url: url)
            let session = URLSession.shared
            
            let task = session.dataTask(with: request) { (data, response, error) in
                if let error = error {
                    print("Error: \(error.localizedDescription)")
                } else if let data = data {
                    let responseString = String(data: data, encoding: .utf8)
                    print("Response: \(responseString ?? "")")
                }
            }
            
            task.resume()
        }
    }
}
```

Несоответствующий код отправляет запрос к API, используя небезопасный метод связи. В данном примере URL-адрес API использует протокол HTTP, который не обеспечивает шифрование и целостность данных. Это делает обмен данными уязвимым для подслушивания, атак типа "человек посередине" и фальсификации данных.

Чтобы решить эту проблему, приведем пример совместимого кода:








<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```java
import UIKit

class ViewController: UIViewController {
    
    let apiUrl = "https://example.com/api"
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // Безопасная отправка запроса к API
        if let url = URL(string: apiUrl) {
            let request = URLRequest(url: url)
            let session = URLSession(configuration: .default)
            
            let task = session.dataTask(with: request) { (data, response, error) in
                if let error = error {
                    print("Error: \(error.localizedDescription)")
                } else if let data = data {
                    let responseString = String(data: data, encoding: .utf8)
                    print("Response: \(responseString ?? "")")
                }
            }
            
            task.resume()
        }
    }
}
```


Совместимый код решает проблему небезопасной связи, используя протокол HTTPS для установления безопасного соединения с API. При изменении URL-адреса API для использования протокола HTTPS связь между клиентом и сервером шифруется, обеспечивая конфиденциальность и целостность данных, передаваемых по сети. Использование HTTPS снижает риск подслушивания, взлома и несанкционированного доступа к конфиденциальной информации в процессе обмена данными.




### Небезопасная аутентификация

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```java
import UIKit

class LoginViewController: UIViewController {
    
    @IBOutlet weak var usernameTextField: UITextField!
    @IBOutlet weak var passwordTextField: UITextField!
    
    @IBAction func loginButtonTapped(_ sender: UIButton) {
        let username = usernameTextField.text ?? ""
        let password = passwordTextField.text ?? ""
        
        // Несоответствующий код: Небезопасная отправка имени пользователя и пароля по HTTP
        let apiUrl = "http://example.com/login"
        let requestUrl = URL(string: apiUrl)!
        
        var request = URLRequest(url: requestUrl)
        request.httpMethod = "POST"
        
        let body = "username=\(username)&password=\(password)"
        request.httpBody = body.data(using: .utf8)
        
        let session = URLSession.shared
        let task = session.dataTask(with: request) { (data, response, error) in
            // Реакция на обращение
        }
        
        task.resume()
    }
}
```

Код, не соответствующий требованиям, демонстрирует небезопасную аутентификацию, отправляя имя пользователя и пароль по небезопасному HTTP-соединению. Код строит URL с конечной точкой входа и создает POST-запрос с именем пользователя и паролем в качестве части тела запроса. Однако использование незащищенного HTTP-соединения подвергает конфиденциальные учетные данные опасности подслушивания, перехвата и потенциальной кражи.

Чтобы решить эту проблему, приведем пример совместимого кода:









<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```java
import UIKit

class LoginViewController: UIViewController {
    
    @IBOutlet weak var usernameTextField: UITextField!
    @IBOutlet weak var passwordTextField: UITextField!
    
    @IBAction func loginButtonTapped(_ sender: UIButton) {
        let username = usernameTextField.text ?? ""
        let password = passwordTextField.text ?? ""
        
        // Соответствующий код: Безопасная передача имени пользователя и пароля по протоколу HTTPS
        let apiUrl = "https://example.com/login"
        let requestUrl = URL(string: apiUrl)!
        
        var request = URLRequest(url: requestUrl)
        request.httpMethod = "POST"
        
        let body = "username=\(username)&password=\(password)"
        request.httpBody = body.data(using: .utf8)
        
        let session = URLSession(configuration: .default)
        let task = session.dataTask(with: request) { (data, response, error) in
            // Реакция на обращение
        }
        
        task.resume()
    }
}
```


Соответствующий код решает проблему небезопасной аутентификации, используя HTTPS-соединение для безопасной передачи имени пользователя и пароля. Код строит URL-адрес с конечной точкой входа в систему с использованием протокола HTTPS, обеспечивая шифрование и безопасность связи между клиентом и сервером. Благодаря отправке конфиденциальных данных по защищенному каналу снижается риск подслушивания, перехвата и кражи учетных данных.







### Недостаточная криптография

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```java
import CommonCrypto

func encryptData(data: Data, key: String) -> Data? {
    let keyData = key.data(using: .utf8)!
    let algorithm: CCAlgorithm = CCAlgorithm(kCCAlgorithmAES)
    let options: CCOptions = CCOptions(kCCOptionECBMode)
    let keyLength = size_t(kCCKeySizeAES256)
    let bufferSize = data.count + kCCBlockSizeAES128
    var buffer = Data(count: bufferSize)
    
    let status = keyData.withUnsafeBytes { keyBytes in
        data.withUnsafeBytes { dataBytes in
            buffer.withUnsafeMutableBytes { bufferBytes in
                CCCrypt(CCOperation(kCCEncrypt),
                        algorithm,
                        options,
                        keyBytes.baseAddress,
                        keyLength,
                        nil,
                        dataBytes.baseAddress,
                        data.count,
                        bufferBytes.baseAddress,
                        bufferSize,
                        nil)
            }
        }
    }
    
    return (status == kCCSuccess) ? buffer : nil
}
```

Несоответствующий код использует библиотеку CommonCrypto для шифрования данных с помощью алгоритма Advanced Encryption Standard (AES) в режиме Electronic Codebook (ECB). Однако этот код имеет несколько проблем. Во-первых, он использует жестко закодированный ключ, что небезопасно, так как его можно легко скомпрометировать. Во-вторых, в нем используется слабый режим шифрования (ECB), в котором отсутствуют такие элементы безопасности, как векторы инициализации (IVs), что делает его уязвимым для некоторых атак, например распознавания образов.

Чтобы решить эти проблемы, приведем пример совместимого кода:








<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```java
import CommonCrypto

func encryptData(data: Data, key: Data) -> Data? {
    let algorithm: CCAlgorithm = CCAlgorithm(kCCAlgorithmAES)
    let options: CCOptions = CCOptions(kCCOptionPKCS7Padding)
    let keyLength = size_t(kCCKeySizeAES256)
    let ivSize = kCCBlockSizeAES128
    let bufferSize = data.count + ivSize
    var buffer = Data(count: bufferSize)
    var numBytesEncrypted: size_t = 0
    
    let status = key.withUnsafeBytes { keyBytes in
        CCCrypt(CCOperation(kCCEncrypt),
                algorithm,
                options,
                keyBytes.baseAddress,
                keyLength,
                nil,
                data.withUnsafeBytes { dataBytes in
                    dataBytes.baseAddress
                },
                data.count,
                buffer.withUnsafeMutableBytes { bufferBytes in
                    bufferBytes.baseAddress
                },
                bufferSize,
                &numBytesEncrypted)
    }
    
    return (status == kCCSuccess) ? buffer.prefix(numBytesEncrypted) : nil
}
```


Соответствующий код решает проблемы несоответствующего кода. Он принимает ключ шифрования в качестве параметра Data, а не String, что позволяет более безопасно генерировать и управлять ключами. Код также использует безопасную прокладку PKCS7 вместо режима ECB, что добавляет случайности и усиливает шифрование. Кроме того, он генерирует случайный вектор инициализации (IV) для каждой операции шифрования, обеспечивая дополнительную защиту от некоторых атак. Код также возвращает только зашифрованные данные без неиспользованных байтов буфера, что повышает эффективность и снижает риск раскрытия конфиденциальной информации.





### Небезопасная авторизация

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```java
func checkPermission(user: User, permission: String) -> Bool {
    let userPermissions = user.permissions
    return userPermissions.contains(permission)
}
```

Несоответствующий код просто проверяет, есть ли у пользователя определенное разрешение, сравнивая массив разрешений пользователя с указанным разрешением. Однако в этом коде отсутствует надлежащая проверка авторизации и не реализован какой-либо механизм управления доступом. Он предполагает, что разрешения пользователя хранятся и управляются безопасно, а это может быть не так.


Чтобы решить эти проблемы, приведем пример совместимого кода:









<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```java
func checkPermission(user: User, permission: String) -> Bool {
    guard let userPermissions = retrieveUserPermissions(user: user) else {
        return false
    }
    
    return userPermissions.contains(permission)
}

func retrieveUserPermissions(user: User) -> [String]? {
    // Получение разрешений пользователей из безопасного и надежного источника данных
    // Внедрять надлежащие механизмы аутентификации и авторизации
    // Применять соответствующие политики управления доступом
    // Валидация и санация пользовательского ввода
    // Выполнение необходимых проверок, чтобы убедиться, что пользователь авторизован для доступа к данным разрешений
    
    return user.permissions
}
```


Соответствующий код решает проблемы несоответствующего кода, реализуя более безопасный механизм авторизации. В нем появилась отдельная функция retrieveUserPermissions, которая извлекает разрешения пользователя из безопасного и надежного источника данных. Эта функция отвечает за выполнение надлежащих проверок аутентификации и авторизации, применение политик управления доступом и проверку вводимых пользователем данных. Благодаря разделению логики получения разрешений код позволяет более гибко реализовать надежные механизмы авторизации и обеспечить безопасность процесса.




### Качество клиентского кода

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```java
class ViewController: UIViewController {
    @IBOutlet weak var label: UILabel!
    
    func updateLabel(text: String) {
        label.text = text
    }
    
    func showAlert() {
        let alert = UIAlertController(title: "Alert", message: "This is an alert message.", preferredStyle: .alert)
        let action = UIAlertAction(title: "OK", style: .default)
        alert.addAction(action)
        self.present(alert, animated: true, completion: nil)
    }
}
```

Пример кода, не соответствующий требованиям, демонстрирует класс ViewController, который обрабатывает обновление метки и отображение предупреждения. Однако он нарушает принципы качества клиентского кода несколькими способами.

1. Отсутствие разделения задач: Класс ViewController отвечает как за обновление пользовательского интерфейса (updateLabel), так и за отображение оповещения (showAlert). Рекомендуется разделить эти обязанности по разным классам или методам для лучшей организации кода.

2. Нарушение принципа единой ответственности (SRP): класс ViewController должен нести единую ответственность, например, управлять жизненным циклом представления или обрабатывать взаимодействия с пользователем. Смешивание обновлений пользовательского интерфейса и бизнес-логики в одном классе может сделать код более сложным для понимания и поддержки.

3. Отсутствие обработки ошибок: Код не обрабатывает ошибки, которые могут возникнуть во время обновления пользовательского интерфейса или представления предупреждений. Правильная обработка ошибок должна быть реализована, чтобы обеспечить лучший пользовательский опыт и предотвратить неожиданные проблемы.



Чтобы решить эти проблемы, вот пример совместимого кода:





<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```java
class ViewController: UIViewController {
    @IBOutlet weak var label: UILabel!
    
    func updateLabel(text: String) {
        DispatchQueue.main.async { [weak self] in
            self?.label.text = text
        }
    }
}

class AlertHelper {
    static func showAlert(on viewController: UIViewController, title: String, message: String) {
        let alert = UIAlertController(title: title, message: message, preferredStyle: .alert)
        let action = UIAlertAction(title: "OK", style: .default)
        alert.addAction(action)
        viewController.present(alert, animated: true, completion: nil)
    }
}
```


Соответствующий код решает проблемы несоответствующего кода, улучшая качество клиентского кода. Он разделяет обязанности, перемещая логику обновления пользовательского интерфейса в класс ViewController, а логику представления предупреждений - в отдельный класс AlertHelper.

Метод updateLabel теперь запускает обновление пользовательского интерфейса в основной очереди, чтобы обеспечить безопасность потоков. Благодаря использованию отдельного класса-помощника AlertHelper представление оповещений отделено от контроллера представления, что способствует лучшей организации кода и разделению проблем.

Важно отметить, что совместимый код может потребовать дополнительных улучшений в зависимости от специфических требований приложения. Однако он демонстрирует лучшее качество клиентского кода благодаря соблюдению таких принципов, как разделение забот и принцип единой ответственности.






### Фальсификация кода

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```java
class ViewController: UIViewController {
    @IBOutlet weak var label: UILabel!
    
    func updateLabel(text: String) {
        label.text = text
    }
}

class DataProcessor {
    func processData(data: String) -> String {
        // Некоторая логика обработки данных
        return data.uppercased()
    }
}

class MainViewController: UIViewController {
    let dataProcessor = DataProcessor()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        let viewController = ViewController()
        viewController.updateLabel(text: dataProcessor.processData(data: "Hello, World!"))
    }
}
```

Пример несоответствующего кода иллюстрирует уязвимость подделки кода. В этом сценарии злоумышленник может изменить метод processData в классе DataProcessor, чтобы манипулировать возвращаемыми обработанными данными. Поскольку MainViewController полагается на DataProcessor для обработки данных перед обновлением метки, любая модификация метода processData может привести к непреднамеренным или вредоносным изменениям в отображаемом тексте.




Чтобы устранить эту уязвимость, связанную с несанкционированным доступом к коду, приведем пример совместимого кода:











<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```java
class ViewController: UIViewController {
    @IBOutlet weak var label: UILabel!
    
    func updateLabel(text: String) {
        label.text = text
    }
}

class DataProcessor {
    func processData(data: String) -> String {
        // Некоторая логика обработки данных
        return data.uppercased()
    }
}

class MainViewController: UIViewController {
    let dataProcessor = DataProcessor()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        let processedData = dataProcessor.processData(data: "Hello, World!")
        let viewController = ViewController()
        viewController.updateLabel(text: processedData)
    }
}
```


В совместимом коде были приняты меры по снижению уязвимости взлома кода. Класс DataProcessor и его метод processData остаются неизменными, что обеспечивает целостность логики обработки данных. Контроллер MainViewController получает обработанные данные из DataProcessor и передает их непосредственно в метод updateLabel контроллера ViewController, не допуская никаких промежуточных вмешательств.

Гарантируя, что критически важные код и данные не могут быть напрямую изменены внешними сущностями, совместимый код снижает риск возникновения уязвимостей, связанных со взломом кода. Это способствует соблюдению принципа целостности кода и помогает поддерживать надежность функциональности приложения.





### Обратный инжиниринг

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```java
class SecretManager {
    private let secretKey = "mySecretKey"
    
    func getSecretKey() -> String {
        return secretKey
    }
}

class ViewController: UIViewController {
    let secretManager = SecretManager()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        let secretKey = secretManager.getSecretKey()
        print("Secret Key: \(secretKey)")
    }
}
```

Пример кода, не соответствующий требованиям, демонстрирует уязвимость обратного инжиниринга. В этом примере класс SecretManager содержит секретный ключ, который очень важен для выполнения конфиденциальных операций. Однако секретный ключ непосредственно встроен в исходный код. Злоумышленник, получивший доступ к скомпилированному двоичному файлу, может провести обратное проектирование приложения, чтобы извлечь секретный ключ.




Чтобы устранить эту уязвимость для обратного проектирования, приведем пример совместимого кода:












<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```java
class SecretManager {
    private let secretKey = "mySecretKey"
    
    func getSecretKey() -> String {
        return secretKey
    }
}

class ViewController: UIViewController {
    let secretManager = SecretManager()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        printSecretKey()
    }
    
    func printSecretKey() {
        let secretKey = secretManager.getSecretKey()
        print("Secret Key: \(secretKey)")
    }
}
```


В совместимом коде секретный ключ по-прежнему хранится в классе SecretManager. Однако прямой доступ к ключу из ViewController не осуществляется. Вместо этого в ViewController создается отдельная функция printSecretKey() для обработки секретной операции. Изолировав доступ к секретному ключу в рамках отдельной функции, злоумышленнику будет сложнее извлечь секретный ключ путем обратной разработки.

Кроме того, для дополнительной защиты конфиденциальной информации от атак обратного проектирования рекомендуется использовать такие меры безопасности, как шифрование, обфускация и методы безопасного хранения. Эти методы позволяют увеличить сложность и усилия, необходимые злоумышленнику для обратного проектирования кода и извлечения конфиденциальных данных.





### Посторонние функции

<span class="d-inline-block p-2 mr-1 v-align-middle bg-red-000"></span>Несоответствующий код:


```java
class DataManager {
    func saveData(data: String) {
        // Код для сохранения данных
    }
    
    func deleteData(data: String) {
        // Код для удаления данных
    }
    
    func processData(data: String) {
        // Код для обработки данных
    }
    
    func sendDataToServer(data: String) {
        // Код для отправки данных на сервер
    }
}

class ViewController: UIViewController {
    let dataManager = DataManager()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        let data = "Sample data"
        
        dataManager.saveData(data: data)
        dataManager.deleteData(data: data)
        dataManager.processData(data: data)
        dataManager.sendDataToServer(data: data)
    }
}
```

Пример кода, не соответствующий требованиям, содержит постороннюю функциональность в классе DataManager. Помимо необходимых операций управления данными, таких как сохранение и удаление данных, он также содержит функции для обработки данных и отправки их на сервер. Это нарушает принцип разделения задач и может привести к излишней сложности и потенциальным рискам безопасности.



Чтобы решить эту проблему, приведем пример совместимого кода:




<span class="d-inline-block p-2 mr-1 v-align-middle bg-green-000"></span>Соответствующий код:


```java
class DataManager {
    func saveData(data: String) {
        // Код для сохранения данных
    }
    
    func deleteData(data: String) {
        // Код для удаления данных
    }
}

class ViewController: UIViewController {
    let dataManager = DataManager()
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        let data = "Sample data"
        
        dataManager.saveData(data: data)
        dataManager.deleteData(data: data)
    }
}
```


Соответствующий код удаляет лишнюю функциональность из класса DataManager, оставляя только необходимые операции управления данными: saveData и deleteData. Благодаря удалению ненужных функций код становится проще и больше сосредоточен на своих основных обязанностях. Это улучшает сопровождаемость кода, уменьшает поверхность атаки и минимизирует риск непреднамеренного поведения или уязвимостей, возникающих из-за неиспользуемой функциональности.


