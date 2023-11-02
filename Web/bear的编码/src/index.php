<?php

error_reporting(0);
$flag = file_get_contents("/flag");

if(!session_id())
    session_start();

if(!isset($_SESSION['count']))
    $_SESSION['count']=0;

if(isset($_SESSION['answer']) && isset($_POST['answer'])){
    if(($_SESSION['answer'])!==$_POST['answer']){
        session_destroy();
        die('答案错误');
    }
    else{
        if(intval(time())-$_SESSION['time']<1){
            session_destroy();
            die('心急吃不了热豆腐');
        }
        if(intval(time())-$_SESSION['time']>3){
            session_destroy();
            die('来不及了...');
        }
        $_SESSION['count']++;
    }
}
if($_SESSION['count']>=10){
    session_destroy();
    echo $flag;
    die();
}

function GetRandStr($length){
    //字符组合
    $str = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $len = strlen($str)-1;
    $randstr = '';
    for ($i=0;$i<$length;$i++) {
     $num=mt_rand(0,$len);
     $randstr .= $str[$num];
    }
    return $randstr;
}


$len = rand(10,20);
$str = GetRandStr($len);
$mode=rand(0,3);
$ans = 0;
switch($mode){
    case 0:
        $ans=base64_encode($str);
        break;
    case 1:
        $ans=hash("sha256", $str);
        break;
    case 2:
        $ans=sha1($str);
        break;
    case 3:
        $ans=md5($str);
        break;
}
$_SESSION['answer']=$ans;
$_SESSION['time']=intval(time());
?>
<h1>编码游戏</h1>
<p>在1~3秒内提交你的答案，答对10次可以获得flag</p>
<p>字符串满足</p>
<p> 你已经回答了 <?php echo $_SESSION['count'];?>个问题</p>

<form action="" method="post">
<?php
$sentence="";
switch($mode) {
    case 0:
        $sentence = "base64(\"$str\")";
        break;
    case 1:
        $sentence = "sha256(\"$str\")";
        break;
    case 2:
        $sentence = "sha1(\"$str\")";
        break;
    case 3:
        $sentence = "md5(\"$str\")";
        break;
}
echo "<div"." class='question'>".$sentence."</div>";
?>
    <input type="text" name="answer">
    <input type="submit" value="提交">
</form>