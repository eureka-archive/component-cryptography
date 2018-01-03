<?php

/*
 * Copyright (c) Romain Cottard
 *
 *  For the full copyright and license information, please view the LICENSE
 *  file that was distributed with this source code.
 */

namespace Eureka\Component\Cryptography;

/**
 * Interface CryptorInterface
 *
 * @author Romain Cottard
 */
interface EncryptionInterface
{
    /**
     * @param  string $plainTextData Plain text data to encrypt
     * @param  string $key Key for encryption
     * @param  array  $options List of options for cryptography sub service
     * @return string
     * @throws Exception\CryptographyException
     * @throws Exception\HashException
     * @throws Exception\HashMethodNotAvailableException
     */
    public function encrypt($plainTextData, $key, &$options = []);
}
