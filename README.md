# Code Review

## CWE-598: *Использование метода запроса GET с чувствительными строками запроса*
```php
$user = $_GET[ 'username' ];
$pass = $_GET[ 'password' ];
```
**Исправление:** При отправке конфиденциальной информации необходимо использовать метод `POST`
```php
$username = $_POST['username'];
$password = $_POST['password'];
```



## CWE-327: *Использование устаревшего криптографического алгоритма MD5*
```php
$pass = md5( $pass );
```
**Исправление:** Использовать более криптостойкий пароль - `SHA256`.
```php
$password_hash = hash($password + get_salt($username), $str);
```



## CWE-759: *Использование одностороннего хеширования без соли*
**Исправление:** Использовать соль, которая будет храниться в базе данных.
```php
get_salt($username)
```



## CWE-89: *Неправильная нейтрализация специальных элементов, используемых в команде SQL*
```php
$query  = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";
```
**Исправление:** добавить использование PDO или его аналогов, чтобы избежать SQL инъекции.
```php
$data = prepare_data('SELECT * FROM users WHERE user = (:user) AND password = (:password) LIMIT 1;');
$data->bindParam($username_param, $username, PDO::PARAM_STR);
$data->bindParam($password_param, $password_hash, PDO::PARAM_STR);
$row = get_row($data);
```



## CWE-307: *Неправильное ограничение или отсутствия чрезмерных попыток аутентификации*
Возможные варианты исправления ошибок:
 - Отключение пользователя после небольшого количества неудачных попыток
 - Реализация тайм-аута
 - Блокировка целевой учетной записи
 - Требование вычислительной задачи со стороны пользователя.

**Исправление:** Отключение пользователя после небольшого количества неудачных попыток.
```php
if($row == 1) {
  $avatar = $row["avatar"];
  $html .= "<p>Welcome to the password protected area {$username}</p>";
  $html .= "<img src=\"{$avatar}\" />";

  $query = "UPDATE users SET {$failed_login_count} = null WHERE user = (:user) AND password = (:password) LIMIT 1;"
  $data = prepare_data($query);
  $data->bindParam($username_param, $username, PDO::PARAM_STR);
  $data->execute();
} else {
  $data = prepare_data("UPDATE users SET {$failed_login_count} = ({$failed_login_count} + 1) WHERE user = (:user) LIMIT 1;");
  $data->bindParam($username_param, $username, PDO::PARAM_STR);
  $data->execute();

  $html .= "<pre>";
  $html .= "Username and/or password incorrect.<br/>";
  $html .= "Please try again after {$lockout_time} minutes<br/>";
  $html .= "</pre>";
  sleep($lockout_time);
}
```
