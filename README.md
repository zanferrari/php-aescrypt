# AESCrypt php class
## encrypt and decrypt data compatible with https://www.aescrypt.com

Modified the earlier version and made it php 8 compatible.

## Usage

- Initiate the class passing your password
- Set creation date and time
- Encrypt or decrypt data as you need

See the usage in "example.php"

```sh
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
```

## License

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.
 
This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details at:
http://www.gnu.org/copyleft/lesser.html