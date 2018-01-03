<?php

/*
 * Copyright (c) Romain Cottard
 *
 *  For the full copyright and license information, please view the LICENSE
 *  file that was distributed with this source code.
 */

namespace Eureka\Component\Cryptography\OpenSSL;

use Eureka\Component\Cryptography\DecryptionInterface;
use Eureka\Component\Cryptography\Exception;

/**
 * Class Decryption service.
 *
 * @author Romain Cottard
 */
class Decryption implements DecryptionInterface
{
    /** @var OpenSSL $service  */
    private $service = null;

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
    public function decrypt($encryptedData, $key, $options = [])
    {
        $encryptedData    = base64_decode($encryptedData);
        $decryptedDataRaw = $this->extractDataRaw($encryptedData);

        $this->assertHashIsValid(
            $this->service->getHash($decryptedDataRaw),
            $this->extractHash($encryptedData)
        );

        return $this->service
            ->setIV($this->extractIV($encryptedData))
            ->decrypt($decryptedDataRaw, $key)
        ;
    }

    /**
     * Assert the calculated hash is equal to the hash from encrypted data
     *
     * @param  string $calculatedHash
     * @param  string $hash
     * @return void
     * @throws Exception\InvalidHashException
     */
    private function assertHashIsValid($calculatedHash, $hash)
    {
        if ($calculatedHash !== $hash) {
            throw new Exception\InvalidHashException('Invalid hash.');
        }
    }

    /**
     * Extract initialization vector (IV)
     *
     * @param  string $encryptedData
     * @return bool|string
     */
    private function extractIV($encryptedData)
    {
        return substr($encryptedData, 0, $this->service->getCipherIVLength());
    }

    /**
     * Extract hash from encrypted data
     *
     * @param  string $encryptedData
     * @return bool|string
     */
    private function extractHash($encryptedData)
    {
        return substr($encryptedData, $this->service->getCipherIVLength(), 32);
    }

    /**
     * Extract raw data from encrypted data
     *
     * @param  string $encryptedData
     * @return bool|string
     */
    private function extractDataRaw($encryptedData)
    {
        return substr($encryptedData, $this->service->getCipherIVLength() + 32);
    }
}
