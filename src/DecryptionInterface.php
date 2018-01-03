<?php
/*
 * Copyright (c) Romain Cottard
 *
 *  For the full copyright and license information, please view the LICENSE
 *  file that was distributed with this source code.
 */

namespace Eureka\Component\Cryptography;

/**
 * Interface DecryptionInterface
 *
 * @author Romain Cottard
 */
interface DecryptionInterface
{
    /**
     * @param  string $encryptedData Encrypted text data to decrypt
     * @param  string $key Key for decryption
     * @param  array  $options List of options for cryptography sub service
     * @return string
     * @throws Exception\CryptographyException
     */
    public function decrypt($encryptedData, $key, $options = []);
}
