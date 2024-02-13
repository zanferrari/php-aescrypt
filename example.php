<?php
define('AES_PSW','ZK350*2017*lWg6');

require_once('class.aesCrypt.php');

$crypt = new AESCrypt(constant('AES_PSW'));
		
// Setting date and time
$date = date("Y-m-d");
$time = date("H:i:s");

// Adding date and time to the header
// of the encrypted file
$crypt->setExtText(array(
    $crypt::CREATED_DATE=>$date,
    $crypt::CREATED_TIME=>$time
    )
);	

// encrypt plain text file
$file_data = file_get_contents('plain.txt');

$encrypted_data = $crypt->encrypt($file_data);

file_put_contents('plain.txt.aes', $encrypted_data);

// decrypt AESencrypted file
$file_data = file_get_contents('plain.txt.aes');

$decrypted_data = $crypt->decrypt($file_data);

// content must be the same as plain.txt
file_put_contents('plain-decrypted.txt', $decrypted_data);