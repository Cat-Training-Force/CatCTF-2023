<?php
// 建立与MySQL数据库的连接
error_reporting(0);
$servername = "localhost";
$username = "root";
$password = "root";
$dbname = "catctf";

$conn = new mysqli($servername, $username, $password, $dbname);

// 检查连接是否成功
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// 从POST请求中获取用户名和密码
$username = $_POST['username'];
$password = $_POST['password'];

$sql="SELECT * FROM users WHERE username='$username' and password='$password'";

$result=mysqli_query($conn,$sql);
$row = mysqli_fetch_array($result);

$flag = file_get_contents("/flag");

// 检查用户是否存在
if ($row) {
    // 用户存在，可以登录
    $response = array("status" => "success", "message" => "$flag");
} else {
    // 用户不存在或密码不匹配
    $response = array("status" => "error", "message" => "用户名或密码不正确");
}

// 将响应以JSON格式返回给前端
header('Content-Type: application/json');
echo json_encode($response);

// 关闭数据库连接
$stmt->close();
$conn->close();

?>
