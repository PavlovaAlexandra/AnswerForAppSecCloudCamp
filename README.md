# Решение тестового задания для поступления на стажировку AppSecCloudCamp
В данном репозитории в файле README.md предоставляется решение тестового задания для поступления в AppSec bootcamp в Cloud.ru. Задание выполнено Александрой Павловой.
# 1. Вопросы для разогрева
Добрый день, меня зовут Александра.

Я перешла из области программной инженерии и разработки в сферу информационной безопасности с поступлением в магистратуру по направлению «Кибербезопасность». В процессе обучения я, помимо получения теоретических знаний, выполняла лабораторные работы по SQL-инъекциям, решала задачи по криптографии и изучала вопросы аппаратной безопасности. По рекомендации коллег я начала изучать инструмент Burp и начала проходить лабораторные работы в PortSwigger Academy, дополняя полученные знания статьями и материалами по различным уязвимостям.

Моя цель - получить практический опыт работы с реальными продуктами и сервисами в области информационной безопасности, поэтому я заинтересовалась вашей стажировкой. Сейчас я нахожусь в стадии активного обучения, и готова уделять стажировке 40 часов в неделю. Спасибо за проверку моей работы и уделенное мне время, готова ответить на все дополнительные вопросы, которые у вас возникнут.
# 2. Security code review
## Часть 1. Security code review: GO
Исходный код:
```
package main

import (
    "database/sql"
    "fmt"
    "log"
    "net/http"
    "github.com/go-sql-driver/mysql"
)

var db *sql.DB
var err error

func initDB() {
    db, err = sql.Open("mysql", "user:password@/dbname")
    if err != nil {
        log.Fatal(err)
    }

err = db.Ping()
if err != nil {
    log.Fatal(err)
    }
}

func searchHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != "GET" {
        http.Error(w, "Method is not supported.", http.StatusNotFound)
        return
    }

searchQuery := r.URL.Query().Get("query")
if searchQuery == "" {
    http.Error(w, "Query parameter is missing", http.StatusBadRequest)
    return
}

query := fmt.Sprintf("SELECT * FROM products WHERE name LIKE '%%%s%%'", searchQuery)
rows, err := db.Query(query)
if err != nil {
    http.Error(w, "Query failed", http.StatusInternalServerError)
    log.Println(err)
    return
}
defer rows.Close()

var products []string
for rows.Next() {
    var name string
    err := rows.Scan(&name)
    if err != nil {
        log.Fatal(err)
    }
    products = append(products, name)
}

fmt.Fprintf(w, "Found products: %v\n", products)
}

func main() {
    initDB()
    defer db.Close()

http.HandleFunc("/search", searchHandler)
fmt.Println("Server is running")
log.Fatal(http.ListenAndServe(":8080", nil))
}
```
Потенциальные уязвимости:
1. SQL injection
    * Строка 38: `query := fmt.Sprintf("SELECT * FROM products WHERE name LIKE '%%%s%%'", searchQuery) `
    * Угрозы: SQL injection  
      Пример атаки: searchQuery может иметь следующее значение: `example’; DROP TABLE products; -- `  
      Последствия: удаление таблицы products и любые другие подобные угрозы
    * Пример исправления:
      ```
      query := "SELECT * FROM products WHERE name LIKE ?"
      stmt, err := db.Prepare(query)
      if err != nil {
          log.Fatal(err)
      }
      defer stmt.Close()

      rows, err := stmt.Query("%" + searchQuery + "%")
      if err != nil {
          log.Fatal(err)
      }
      ```
2. Неиспользование SSL сертификатов и HTTPS
    * Строка 66: `log.Fatal(http.ListenAndServe(":8080", nil))`
    * Угрозы: утечка конфиденциальной информации
    * Пример исправления:  
      Сгенерировать SSL сертификат, использовать ListenAndServeTLS вместо ListenAndServe:  
      `log.Fatal(http.ListenAndServeTLS(":443", "cert.crt", "cert.key", nil))`
      
3. Хранение пароля в исходном коде
    * Строка 15: `db, err = sql.Open("mysql", «user:password@/dbname")`
    * Угрозы: утечка конфиденциальной информации, сложность обновления пароля, отсутствие контроля доступа
    * Пример исправления: использовать переменные окружения/файлы конфигурации/библиотеки для хранения секретов (например, HashiCorp Vault) и добавить ограничения доступа пользователей к бд   

      Вариант 1: переменные окружения
      ```
      export DATABASE_USERNAME=user
      export DATABASE_PASSWORD=password
      export DATABASE_DBNAME=dbname
      ```
      Вариант 2: файл конфигурации
      ```
      // config.json
      {
        "database":{
            "username": "user",
            "password": "password",
            "dbname": "dbname"
        }
      }

      // test.go
      func init() {
          config, err := ioutil.ReadFile("config.json")
          if err != nil {
              log.Fatal(err)
          }
      
          err = json.Unmarshal(config, &config)
          if err != nil {
              log.Fatal(err)
          }
          
          db, err := sql.Open("mysql", config.Database.Username+":"+config.Database.Password+"@/"+config.Database.Dbname)
          if err != nil {
              log.Fatal(err)
          }
      }
      ```
      
      Вариант 3: библиотеки для хранения секретов  
      ```
      func init() {
          vault, err := vault.NewClient(vault.Config{
          Address: "http://localhost:8200",
          })
          if err != nil {
              log.Fatal(err)
          }   
          
          secret, err := vault.Logical().Read("secret/database")
          if err != nil {
              log.Fatal(err)     
          }
          
          username := secret.Data["username"]
          password := secret.Data["password"]
          dbname := secret.Data["dbname"]
          
          db, err := sql.Open("mysql", username+":"+password+"@/"+dbname)     
          if err != nil {
              log.Fatal(err)     
          } 
      } 
      ```

4. Отсутствие проверки прав доступа
    * Строка 26: `func searchHandler(w http.ResponseWriter, r *http.Request) {`
    * Угрозы: любой пользователь, даже неавторизованный, может получить доступ к /search, это приводит к утечке информации
    * Пример исправления:
      ```
      func searchHandler(w http.ResponseWriter, r *http.Request) {
          if !isLoggedIn(r) {
              http.Error(w, "Unauthorized", http.StatusUnauthorized)
              return
          }
          if !userHasAccess(r) {
              http.Error(w, "Forbidden", http.StatusForbidden)
              return
          }
      }
      ```
5. Отсутствие защиты от CSRF
    * Угрозы: злоумышленник может отправить запрос на поиск от имени пользователя без его ведома
    * Примеры исправления:  
      Вариант 1:
      ```
      csrfToken := r.FormValue("csrf_token")
           if !isValidCSRFToken(csrfToken) {
               http.Error(w, "Invalid CSRF token", http.StatusForbidden)
               return
      }
      ```

      Вариант 2:
      ```
      if r.Header.Get("X-CSRF-Token") != "значение_ожидаемого_токена" {
               http.Error(w, "Invalid CSRF token", http.StatusForbidden)
               return
      }
      ```

6. Недостаточная валидация входных данных
    * Строка 32: `searchQuery := r.URL.Query().Get("query") `
    * Угрозы:  уязвимость к атаке SQL инъекции
    * Пример исправления:
      ```
      searchQuery := r.URL.Query().Get("query")
      if searchQuery == "" || !validSearchQuery(searchQuery) {
           http.Error(w, "Invalid search query", http.StatusBadRequest)
           return
      }
      ```
7. Отсутствие ограничений на размер запроса
    * Строка 32: `searchQuery := r.URL.Query().Get("query")`
    * Угрозы: очень длинный searchQuery может привести к переполнению буфера или другим атакам, связанным с размером данных
    * Пример исправления:
      ```
      maxSearchQueryLength := 1024
      if len(searchQuery) > maxSearchQueryLength
      ```

Дополнительные рекомендации:  
* Необходимо внимательно управлять и ограничивать доступ к эндпоинту во избежание отказа в обслуживании (DoS)
  
## Часть 2: Security code review: Python
### Пример №2.1
Исходный код
```
from flask import Flask, request
from jinja2 import Template

app = Flask(name)

@app.route("/page")
def page():
    name = request.values.get('name')
    age = request.values.get('age', 'unknown')
    output = Template('Hello ' + name + '! Your age is ' + age + '.').render()
    return output

if name == "main":
    app.run(debug=True)
```
Потенциальные уязвимости:
1. Недостаточная валидация пользовательского ввода
    * Строки 8, 9:
      ```
      name = request.values.get('name')  
      age = request.values.get('age', ‘unknown')  
      ```
    * Угрозы:  возможна атака XSS  
      Пример:  
      ```
      name: <script>alert("XSS_vulnerable!");</script>
      age: unknown
      ```
      Получим HTML код: `Hello <script>alert("XSS_vulnerable!");</script>! Your age is unknown.`  
      Эта уязвимость может быть использована для перенаправления на вредоносные сайты, кражи сессий и т.д. 
    * Пример исправлений:
      ```
      from flask import escape
      name = escape(request.values.get('name'))
      age = escape(request.values.get('age', ‘unknown'))
      ```
2. Отсутствие проверки типа данных
    * Строки 8, 9:
      ```
      name = request.values.get('name')
      age = request.values.get('age', ‘unknown')
      ```
    * Угрозы: возможны атаки SQL инъекций, утечка информации
    * Пример исправлений:
      ```
      try:
          age = int(request.values.get('age', 'unknown'))
      except ValueError:
          age = 'unknown'
      ```
3. Заменить конкатенацию
    * Строка 10: `output = Template('Hello ' + name + '! Your age is ' + age + '.').render()`
    * Угрозы:  возможны атаки SQL инъекций и инъекции команд, утечка информации
    * Пример исправлений:
      ```
      template = Template('Hello {{ name }}! Your age is {{ age }}.')
      output = template.render(name=name, age=age)
      ```
4. Отсутствие ограничений на размер запроса
    * Строки 8, 9:
      ```
      name = request.values.get('name')
      age = request.values.get('age', ‘unknown')
      ```
    * Угрозы: возможна атака переполнения буфера
    * Пример исправлений:
      ```
      MAX_NAME_LENGTH = 50
      MAX_AGE_LENGTH = 3
      name = escape(request.values.get('name')[:MAX_NAME_LENGTH])
      age = escape(request.values.get('age', ‘unknown')[:MAX_AGE_LENGTH])
      ```

Дополнительные рекомендации:
* Добавить аутентификацию и авторизацию
* Добавить сессионные файлы cookie
* Необходимо внимательно управлять и ограничивать доступ к эндпоинту во избежание отказа в обслуживании (DoS)

### Пример №2.2
Исходный код:
```
from flask import Flask, request
import subprocess

app = Flask(name)

@app.route("/dns")
def dns_lookup():
    hostname = request.values.get('hostname')
    cmd = 'nslookup ' + hostname
    output = subprocess.check_output(cmd, shell=True, text=True)
    return output

if name == "main":
    app.run(debug=True)
```
Потенциальные уязвимости:
1. Валидация входных данных: отсутствие проверки на пустое значение
    * Строка 8: `hostname = request.values.get(‘hostname')`
    * Пример исправлений:
      ```
      if not hostname:
          return "Hostname is required", 400
      ```
2. Валидация входных данных: отсутствие проверки на тип значения
    * Строка 8: `hostname = request.values.get(‘hostname')`
    * Угрозы: уязвимость к атаке инъекции команд
    * Пример исправлений:
      ```
      if not isinstance(hostname, str):
          return "Invalid hostname", 400 
      ```
3. Валидация входных данных: отсутствие проверки на допустимые символы
    * Строка 8: `hostname = request.values.get(‘hostname')`
    * Угрозы: уязвимость к атаке инъекции команд
    * Пример исправлений:
      ```
      allowed_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.")
      if not set(hostname).issubset(allowed_chars):
          return "Invalid hostname", 400
      ```
4. Валидация входных данных: отсутствие проверки на ограничение длины
    * Строка 8: `hostname = request.values.get(‘hostname')`
    * Угрозы: уязвимость к переполнению буфера
    * Пример исправлений:
      ```
      if len(hostname) > 255:
          return "Hostname is too long", 400
      ```
5. Использование списка вместо строки
    * Строка 9: `cmd = 'nslookup ' + hostname `
    * Пример исправлений: `cmd = ['nslookup', hostname] `
6. Заменить subprocess.check_output()
    * Строка 10: `output = subprocess.check_output(cmd, shell=True, text=True)`
    * Угрозы: использование shell=True, потенциальные уязвимости инъекции команд
    * Примеры исправлений:  
      Вариант 1: заменить на subprocess.run  
      ```
      try:
          result = subprocess.run(cmd, capture_output=True, text=True, check=True)
          output = result.stdout
          return output
      except subprocess.CalledProcessError as e:
          return f"Error executing command: {e}" 
      ```
      Вариант 2: использовать библиотеку socket
      ```
      try:
          ip_address = socket.gethostbyname(hostname)
          return f"IP address for {hostname} is {ip_address}"
      except socket.gaierror:
          return "Unable to resolve hostname"
      ```
      Вариант 3: использовать библиотеку dnspython
      ```
      try:
          result = dns.resolver.resolve(hostname, 'A')
          ip_address = result[0].address
          return f"IP address for {hostname} is {ip_address}"
      except dns.resolver.NXDOMAIN:
          return "Hostname not found"
      except dns.resolver.NoAnswer:
          return "No A records found for the hostname"
      except dns.resolver.Timeout:
          return "DNS query timed out" 
      ```
      Вариант 4: использовать Google Cloud DNS API
      ```
      GOOGLE_DNS_API_URL = "https://dns.google/resolve"

      @app.route("/dns")
      def dns_lookup():
          hostname = request.values.get('hostname')
          params = {'name': hostname}
          try:
              response = requests.get(GOOGLE_DNS_API_URL, params=params)
              data = response.json()
              if 'Answer' in data:
                  ip_address = data['Answer'][0]['data']
                  return f"IP address for {hostname} is {ip_address}"
              else:
                  return "No DNS record found for the hostname"
          except requests.RequestException as e:
              return f"Error occurred: {e}»
      ```  
      Рекомендуемый вариант: использовать библиотеку dnspython, так как эта библиотека предоставляет более гибкий и безопасный способ выполнения DNS-запросов непосредственно из Python. 

Дополнительные рекомендации:  
* Проверки для hostname можно вынести в отдельную функцию:
  ```
  def validate_hostname(hostname):
      # example
      return True )
  ```
* Добавить аутентификацию и авторизацию
* Необходимо внимательно управлять и ограничивать доступ к эндпоинту во  избежание отказа в обслуживании (DoS)

# 3. Моделирование угроз
Data Flow Diagram сервиса, обеспечивающего отправку информации в Telegram и Slack.
Потенциальные проблемы безопасности:
1. **PostgreSQL** - Хранение пользовательских конфигураций в бд
    * **Потенциальные проблемы**: несанкционированный доступ к бд, утечка конфиденциальной информации, нарушение законодательства о защите персональных данных
    * **Примеры атак**: SQL-инъекции
    * **Уязвимости**: избыточные права доступа, отсутствие шифрования данных
    * **Способы исправления уязвимостей и смягчения рисков**: строгие права доступа, шифрование данных, хранение строки доступа к бд в сервисах хранения секретов, регулярный аудит безопасности
    * **Вопросы разработчикам**: Какие политики доступа к бд применяются? Какие меры защиты данных применяются в бд? Используется ли шифрование?
2. **Auth** - Аутентификация и авторизация клиентов
    * **Потенциальные проблемы**: несанкционированный доступ к сервису, утечка конфиденциальной информации, нарушение законодательства о защите персональных данных 
    * **Примеры атак**: атака перебора паролей, атака на сессии пользователей
    * **Уязвимости**: отсутствие механизмов обнаружения и предотвращения атак перебора паролей, перехвата сеансов, отсутствие защиты от CSRF
    * **Способы исправления уязвимостей и смягчения рисков**: многофакторная аутентификация, использование токенов для авторизации
    * **Вопросы разработчикам**: Внедрены ли механизмы многофакторной аутентификации? Используются ли токены и как часто они обновляются? Как обрабатываются ошибки аутентификации для предотвращения подбора паролей?
3. **S3** - Хранение статического контента
    * **Потенциальные проблемы**: утечка конфиденциальной информации, удаление важной информации, нарушение законодательства о защите персональных данных
    * **Уязвимости**: доступ к хранилищу без авторизации, избыточные права доступа
    * **Способы исправления уязвимостей и смягчения рисков**: строгие права доступа, шифрование данных, регулярный аудит безопасности
    * **Вопросы разработчикам**: Какие политики доступа к хранилищу применяются? Шифруются ли данные в хранилище? Отслеживается ли подозрительная активность в хранилище?
4. **Microfront** - Отправка информации
    * **Потенциальные проблемы**: недостаточная проверка загружаемых пользователей изображений, не настроенные ограничения на отправку уведомлений пользователем
    * **Уязвимости**: загрузка файлов с вредоносным содержимым
    * **Способы исправления уязвимостей и смягчения рисков**: внедрение механизмов проверки загружаемых файлов, введение ограничений на загружаемые файлы
    * **Вопросы разработчикам**: Проверяются ли файлы, которые отправляет пользователь, и, если да, то как?
5. **Backend application** - Обработка информации
    * **Потенциальные проблемы**: внедрение вредоносного кода, нарушение целостности системы
    * **Примеры атак**: SQL-инъекции, XSS атаки
    * **Уязвимости**: недостаточная валидация входных данных
    * **Способы исправления уязвимостей и смягчения рисков**: проведение регулярного код ревью и тестирования на безопасность
    * **Вопросы разработчикам**: Какие меры предотвращения SQL инъекций и XSS атак применяются? Какие инструменты используются для обнаружения вредоносного кода? Как валидируется информация, поступающая от пользователей?
  
**Дополнительные вопросы**:
1. Как реализовано **хранение API ключей** Telegram-a и Slack-a? Используются ли такие решения как HashiCorp Vault?
2. Как **передаются данные** между всеми компонентами системы? Используется ли протокол HTTPS и другие механизмы защиты передачи информации?
3. Как хранятся **connection string**-и? Например, для доступа к S3. Есть ли доступ у разработчиков ко всем connection string-ам? Используются ли для хранения connection string-ов сервисы хранения секретов?
4. Как осуществляется **доступ к базам данных**? Доступны ли они только с локальных адресов? Настроен ли Firewall?
5. Почему стрелка в S3 односторонняя?(или это опечатка:)) Как осуществляется запись информации в это хранилище? Публичное или приватное это хранилище?
6. Предусмотрены ли инструменты защиты для **ограничения количества запросов** во избежание DoS атак? Реализован ли **мониторинг** подозрительной активности?
7. Является ли микрофронт **API Gateway**-ем или же имеет функциональность микрофронтенда? Если является микрофронтендом, то предусмотрена ли реализация API Gateway для защиты базовой инфраструктуры, реализации авторизации и регулировании числа запросов и др?
8. Проводится ли регулярный **аудит безопасности**?
9. Проводится ли регулярное **обновление программного обеспечения**?
