<?php
$max_failed_login_count = 3;
$account_locked = false;
$lockout_time = 5; // sec

$failed_login_count = 'failed_login_count';
$timeout = 'timeout';

$username = $_POST['username'];
$username_param = ':user';

$password = $_POST['password'];
$password_param = ':password';



function prepare_data($query) {
  return $db->prepare($query);
}

function get_row($data) {
  $data->execute();
  return $data->fetch();
}

function check_unacceptable_symbols($input) {
  $unacceptable_symbols = array('"', '\'', '--', '*');
  foreach ($unacceptable_symbols as $symbol) {
    if (!str_contains($username, $symbol)) continue;
    $html .= "<pre><br/>Username and/or password contains unacceptable symbols: {$symbol}.</pre>";
    return true;
  }
  return false;
}

function check_account_lock() {
  $data = prepare_data("SELECT {$timeout}, {$failed_login_count} FROM users WHERE user = (:user) LIMIT 1;");
  $data->bindParam($username_param, $username, PDO::PARAM_STR);
  $row = get_row($data);

  if ($row[$failed_login_count] <= $max_failed_login_count)
    return false;

  $timeout = strtotime($row[$timeout]);
  $time_now = time();
  return $time_now < $timeout;
}



if (!isset($_POST['Login'])) return;
if (!isset($username)) return;
if (!isset($password)) return;

// validation
if (check_unacceptable_symbols($username)) return;
if (check_unacceptable_symbols($password)) return;
if (check_account_lock()) return;

$password_hash = hash($password + get_salt($username), $str);

$data = prepare_data('SELECT * FROM users WHERE user = (:user) AND password = (:password) LIMIT 1;');
$data->bindParam($username_param, $username, PDO::PARAM_STR);
$data->bindParam($password_param, $password_hash, PDO::PARAM_STR);
$row = get_row($data);

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
$data = prepare_data("UPDATE users SET {$timeout} = now() + 1 WHERE user = (:user) LIMIT 1;");
$data->bindParam($username_param, $username, PDO::PARAM_STR);
$data->execute();
?>