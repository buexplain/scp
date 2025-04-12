<?php
/**
 * Copyright 2025 buexplain@qq.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

declare(strict_types=1);

class AES
{
    /**
     * 密钥
     * @var string
     */
    protected string $key = '';

    /**
     * @param string $key 密钥，长度必须是16、24或32字节
     */
    public function __construct(string $key)
    {
        $this->key = $key;
    }

    /**
     * 获取密钥
     * @return string
     */
    public function getKey(): string
    {
        return $this->key;
    }

    /**
     * 加密
     * @param string $data 明文
     * @param string $cipher_algo 加密算法
     * @return string
     * @throws Exception
     */
    public function encrypt(string $data, string $cipher_algo = 'AES-192-CBC'): string
    {
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($cipher_algo));
        $encrypted = openssl_encrypt($data, $cipher_algo, $this->key, OPENSSL_RAW_DATA, $iv);
        if ($encrypted === false) {
            throw new Exception(openssl_error_string());
        }
        return pack('N', strlen($iv)) . $iv . $encrypted;
    }

    /**
     * 解密
     * @param string $encryptedData 密文
     * @param string $cipher_algo 加密算法
     * @return string
     * @throws Exception
     */
    public function decrypt(string $encryptedData, string $cipher_algo = 'AES-192-CBC'): string
    {
        $head = substr($encryptedData, 0, 4);
        $head = unpack('N', $head);
        if (!is_array($head) || !isset($head[1]) || !is_int($head[1]) || $head[1] <= 0) {
            throw new Exception("Decrypt failed");
        }
        $iv = substr($encryptedData, 4, $head[1]);
        $encryptedData = substr($encryptedData, 4 + $head[1]);
        $ret = openssl_decrypt($encryptedData, $cipher_algo, $this->key, OPENSSL_RAW_DATA, $iv);
        if ($ret === false) {
            throw new Exception(openssl_error_string());
        }
        return $ret;
    }
}