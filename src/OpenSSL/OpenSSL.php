<?php

/*
 * Copyright (c) Romain Cottard
 *
 *  For the full copyright and license information, please view the LICENSE
 *  file that was distributed with this source code.
 */

namespace Eureka\Component\Cryptography\OpenSSL;

use Eureka\Component\Cryptography\Exception;

/**
 * Class OpenSSL
 *
 * /!\ At least as early as Aug 2016, Openssl declared the following weak: RC2, RC4, DES, 3DES, MD5 based
 * /!\ ECB mode should be avoided (php doc: http://fr2.php.net/manual/en/function.openssl-get-cipher-methods.php)
 *
 * @author Romain Cottard
 * @link http://fr2.php.net/manual/en/function.openssl-get-cipher-methods.php
 */
class OpenSSL
{
    /** @var string DEFAULT_HASH_METHOD Default hash method (digest method) */
    const DEFAULT_HASH_METHOD = 'sha256';

    /** @var string DEFAULT_HASH_LENGTH Default hash length according to the hash method */
    const DEFAULT_HASH_LENGTH = 32;

    /** @var string DEFAULT_CIPHER_PHP_5 Default cipher for PHP before PHP 7.1 */
    const DEFAULT_CIPHER_PHP_5 = 'aes-256-ctr';

    /** @var string DEFAULT_CIPHER_PHP_5 Default cipher for PHP 7.1+ */
    const DEFAULT_CIPHER_PHP_7 = 'aes-256-gcm';

    /** @var string[] */
    const WEAK_CIPHER_LIST = [
        //~ Weak ciphers
        'rc2',
        'rc4',
        'des',
        'md5',

        //~ To avoid
        'ecb',
    ];

    /** @var string $cipher Selected cipher. Prefer "aes-256-ctr" as cipher before PHP 7.1 and "aes-256-gcm" after PHP 7.1 */
    private $cipher = '';

    /** @var bool $isAuthenticatedCipher */
    private $isAuthenticatedCipher = false;

    /** @var string $iv Initialization vector. */
    private $iv = null;

    /**
     * OpenSSL constructor.
     *
     * @param  string $cipher
     * @throws Exception\CipherNotAvailableException
     */
    public function __construct($cipher = null)
    {
        if ($cipher === null) {
            $cipher = (PHP_VERSION_ID < 70100 ? self::DEFAULT_CIPHER_PHP_5 : self::DEFAULT_CIPHER_PHP_7);
        }

        $this->assertCipherIsAvailable($cipher);
        $this->setCipher($cipher);
    }

    /**
     * Encrypts given data with given method and key, returns a raw or base64 encoded string
     *
     * @param  string $data
     * @param  string $key
     * @param  int $options
     * @param  mixed $tag
     * @param  string $aad
     * @param  int $tagLength
     * @return string Encrypted string
     * @throws Exception\CryptographyException
     */
    public function encrypt($data, $key, $options = OPENSSL_RAW_DATA, &$tag = null, $aad = '', $tagLength = 16)
    {
        if (!is_string($data)) {
            throw new Exception\CryptographyException('Invalid data. Must be a valid string.');
        }

        if ($this->getIV() === null) {
            $this->setIV($this->generateIV());
        }

        if ($this->isAuthenticatedCipher()) {
            return openssl_encrypt($data, $this->getCipher(), $key, $options, $this->getIV(), $tag, $aad, $tagLength);
        }

        return openssl_encrypt($data, $this->getCipher(), $key, $options, $this->getIV());
    }

    /**
     * Takes a raw or base64 encoded string and decrypts it using a given method and key.
     *
     * @param  string $data
     * @param  string $key
     * @param  int $options
     * @param  mixed $tag
     * @param  string $aad
     * @return string Encrypted string
     * @throws Exception\CryptographyException
     */
    public function decrypt($data, $key, $options = OPENSSL_RAW_DATA, $tag = '', $aad = '')
    {
        if (!is_string($data)) {
            throw new Exception\CryptographyException('Invalid data. Must be a valid string.');
        }

        if (empty($this->iv)) {
            throw new Exception\CryptographyException('Invalid initialization vector (iv). Cannot be an empty string.');
        }

        if ($this->isAuthenticatedCipher()) {
            return openssl_decrypt($data, $this->getCipher(), $key, $options, $this->getIV(), $tag, $aad);
        }

        return openssl_decrypt($data, $this->getCipher(), $key, $options, $this->getIV());
    }

    /**
     * Get cipher.
     *
     * @return string
     */
    public function getCipher()
    {
        return $this->cipher;
    }

    /**
     * Set cipher & defined if is GCM cipher.
     *
     * @param  string $cipher
     * @return $this
     */
    public function setCipher($cipher)
    {
        $this->cipher                = $cipher;
        $this->isAuthenticatedCipher = (stripos($cipher, 'gcm') !== false);

        return $this;
    }

    /**
     * Get Initialization vector (IV).
     *
     * @return null|string
     */
    public function getIV()
    {
        return $this->iv;
    }

    /**
     * Get Initialization vector (IV).
     *
     * @param  string $iv
     * @return $this
     * @throws Exception\CryptographyException
     */
    public function setIV($iv)
    {
        if (empty($iv)) {
            throw new Exception\CryptographyException('Invalid initialization vector (iv). Cannot be an empty string.');
        }

        $this->iv = $iv;

        return $this;
    }

    /**
     * Gets the cipher initialization vector (iv) length.
     *
     * @return int
     */
    public function getCipherIVLength()
    {
        return openssl_cipher_iv_length($this->getCipher());
    }

    /**
     * Get if is authenticated cipher.
     *
     * @return bool
     */
    public function isAuthenticatedCipher()
    {
        return $this->isAuthenticatedCipher;
    }

    /**
     * Gets available cipher methods.
     *
     * @param  bool $withAliases
     * @param  bool $excludeWeakCipher
     * @return string[]
     */
    public function getAvailableCipherMethods($withAliases = false, $excludeWeakCipher = true)
    {
        $list = openssl_get_cipher_methods($withAliases);

        if (!$excludeWeakCipher) {
            return $list;
        }

        foreach ($list as $index => $cipher) {
            foreach (self::WEAK_CIPHER_LIST as $weakCipher) {
                if (stripos($cipher, $weakCipher) !== false) {
                    unset($list[$index]);
                }
            }
        }

        return $list;
    }

    /**
     * Gets available digest methods (hash method).
     *
     * @param  bool $withAliases
     * @return string[]
     */
    public function getAvailableDigestMethods($withAliases = false)
    {
        $list = openssl_get_md_methods($withAliases);

        return $list;
    }

    /**
     * Get a hash for the given encrypted data with specified method.
     *
     * @param  string $encryptedDataRaw
     * @param  string $method
     * @param  bool $isRawOutput
     * @return string
     * @throws Exception\HashException
     * @throws Exception\CryptographyException
     */
    public function getHash($encryptedDataRaw, $method = self::DEFAULT_HASH_METHOD, $isRawOutput = true)
    {
        $this->assertDigestMethodIsAvailable($method);

        $hash = openssl_digest($encryptedDataRaw, $method, $isRawOutput);

        if ($hash === false) {
            throw new Exception\HashException('Cannot generate hash of the data!');
        }

        return $hash;
    }

    /**
     * Assert the given cipher is valid.
     *
     * @param  string $cipher
     * @return void
     * @throws Exception\CipherNotAvailableException
     */
    private function assertCipherIsAvailable($cipher)
    {
        if (!in_array($cipher, $this->getAvailableCipherMethods())) {
            throw new Exception\CipherNotAvailableException();
        }
    }

    /**
     * Assert the given digest method is valid.
     *
     * @param  string $method
     * @return void
     * @throws Exception\HashMethodNotAvailableException
     */
    private function assertDigestMethodIsAvailable($method)
    {
        if (!in_array($method, $this->getAvailableDigestMethods())) {
            throw new Exception\HashMethodNotAvailableException();
        }
    }

    /**
     * Generate initialization vector (iv) based on the cipher IV length.
     *
     * @return string
     */
    private function generateIV()
    {
        return openssl_random_pseudo_bytes($this->getCipherIVLength());
    }
}
