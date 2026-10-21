<?php
// Intentionally vulnerable demo application for php-scanner. Do not deploy.

$db = new mysqli('localhost', 'app', getenv('DB_PASSWORD'), 'shop');

$id = $_GET['id'];
$result = $db->query("SELECT * FROM products WHERE id = " . $id);

$name = $_POST['name'] ?? '';
echo "<h1>Hello " . $name . "</h1>";

$safe = htmlspecialchars($_GET['q'] ?? '', ENT_QUOTES, 'UTF-8');
echo "<p>You searched for {$safe}</p>";

$host = $_GET['host'];
system("ping -c 1 " . $host);

$page = $_GET['page'];
include "pages/" . $page . ".php";

$prefs = unserialize($_COOKIE['prefs']);

if ($_POST['token'] == $expected) {
    header("Location: " . $_GET['next']);
}

$hash = md5($_POST['password']);
