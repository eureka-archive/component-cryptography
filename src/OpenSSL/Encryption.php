<?php

/*
 * Copyright (c) Romain Cottard
 *
 *  For the full copyright and license information, please view the LICENSE
 *  file that was distributed with this source code.
 */

namespace Eureka\Component\Cryptography\OpenSSL;

use Eureka\Component\Cryptography\EncryptionInterface;
use Eureka\Component\Cryptography\Exception;

/**
 * Class Cryptor
 *
 * @author Romain Cottard
 */
class Encryption implements EncryptionInterface
{
    /** @var OpenSSL $service  */
    private $service = null;

    /** @var string $hash */
    private $hash = '';

    /**
     * Cryptor constructor.
     *
     * @param OpenSSL $service
     */
    public function __construct(OpenSSL $service)
    {
        $this->service = $service;
    }

    /**
     * @inheritdoc
     */
    public function encrypt($plainTextData, $key, &$options = [])
    {
        if ($this->service->isAuthenticatedCipher()) {

            $options['output']     = 0;
            $options['tag']        = null;
            $options['aad']        = isset($options['aad']) ? $options['aad'] : '';
            $options['tag_length'] = isset($options['tag_length']) ? $options['tag_length'] : 16;

            $encryptedData = $this->service->encrypt($plainTextData, $key, 0, $options['tag'], $options['aad'], $options['tag_length']);

        } else {

            $options['output'] = isset($options['output']) ? $options['output'] : OPENSSL_RAW_DATA;

            $encryptedDataRaw = $this->service->encrypt($plainTextData, $key, $options['output']);
            $this->generateHash($encryptedDataRaw);
            $encryptedData = base64_encode($this->service->getIV() . $this->getHash() . $encryptedDataRaw);
        }

        return $encryptedData;
    }

    /**
     * @return string
     */
    public function getHash()
    {
        return $this->hash;
    }

    /**
     * Data.
     *
     * @param  string $encryptedDataRaw
     * @return $this
     * @throws Exception\CryptographyException
     * @throws Exception\HashException
     */
    private function generateHash($encryptedDataRaw)
    {
        $this->hash = $this->service->getHash($encryptedDataRaw);

        return $this;
    }
}
