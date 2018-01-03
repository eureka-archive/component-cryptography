<?php

/*
 * Copyright (c) Romain Cottard
 *
 *  For the full copyright and license information, please view the LICENSE
 *  file that was distributed with this source code.
 */

use Eureka\Component\Cryptography\OpenSSL\Decryption;
use Eureka\Component\Cryptography\OpenSSL\Encryption;
use Eureka\Component\Cryptography\OpenSSL\OpenSSL;

require_once __DIR__ . '/../vendor/autoload.php';

//~ Services
$openSSL    = new OpenSSL(OpenSSL::DEFAULT_CIPHER_PHP_5);
$encryption = new Encryption($openSSL);
$decryption = new Decryption($openSSL);

//~ String
$object = new \stdClass();
$object->id      = 42;
$object->message = 'Test encryption of this string.';

$message = json_encode($object);
$key     = 'EncryptionKey';
$options = [];

//~ Encrypt data
$encryptedData = $encryption->encrypt($message, $key, $options);

//~ Decrypt data
$messageDecrypted = $decryption->decrypt($encryptedData, $key, $options);

echo 'Original message: ' . $message . PHP_EOL;
echo 'Encryption Key: ' . $key . PHP_EOL;
echo 'Encrypted Message: ' . $encryptedData . PHP_EOL;
echo 'Decrypted message: ' . $messageDecrypted . PHP_EOL;
