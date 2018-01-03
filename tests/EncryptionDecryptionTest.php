<?php

/*
 * Copyright (c) Romain Cottard
 *
 *  For the full copyright and license information, please view the LICENSE
 *  file that was distributed with this source code.
 */

namespace Eureka\Component\Cryptography\Tests;

use Eureka\Component\Cryptography\OpenSSL\Decryption;
use Eureka\Component\Cryptography\OpenSSL\Encryption;
use Eureka\Component\Cryptography\OpenSSL\OpenSSL;

class EncryptionDecryptionTest extends \PHPUnit\Framework\TestCase
{
    /**
     * Test encryption & decryption.
     *
     * @return void
     */
    public function testEncryptionAndDecryptionWithOpenSSLExtension()
    {
        //~ Services
        $openSSL    = new OpenSSL(OpenSSL::DEFAULT_CIPHER_PHP_5);
        $encryption = new Encryption($openSSL);
        $decryption = new Decryption($openSSL);

        //~ String
        $message = 'Test encryption of this string.';
        $key     = 'EncryptionKey';

        //~ Encrypt data
        $encryptedData = $encryption->encrypt($message, $key);

        //~ Decrypt data
        $messageDecrypted = $decryption->decrypt($encryptedData, $key);

        self::assertSame($messageDecrypted, $message, 'Different message :(');
    }
}
