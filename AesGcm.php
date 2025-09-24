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

/**
 * 同时提供保密性 + 完整性/真实性
 * 支持并行加密/解密，性能高
 */
class AesGcm
{
    /**
     * 密钥
     * @var string
     */
    protected string $key = '';
    protected string $cipher_algo = '';

    /**
     * @param string $key 密钥，长度必须是16、24或32字节
     * @throws Exception
     */
    public function __construct(string $key)
    {
        $this->key = $key;
        $this->cipher_algo = match (strlen($key)) {
            16 => 'AES-128-GCM',
            24 => 'AES-192-GCM',
            32 => 'AES-256-GCM',
            default => throw new Exception("Invalid key length"),
        };
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
     * @param string $data 待加密数据
     * @param string $add 附加数据，
     * @return string
     * @throws Exception
     */
    public function encrypt(string $data, string $add): string
    {
        $iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($this->cipher_algo));
        $tag = '';
        $encrypted = openssl_encrypt(
            $data,
            $this->cipher_algo,
            $this->key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $add
        );
        if ($encrypted === false) {
            throw new Exception(openssl_error_string());
        }
        $add = pack('a*', $add);
        $ret = [
            pack('N', strlen($iv)) . $iv,
            pack('N', strlen($tag)) . $tag,
            pack('N', strlen($add)) . $add,
            $encrypted
        ];
        return implode('', $ret);
    }

    /**
     * @param string $encryptedData
     * @return string
     * @throws Exception
     */
    public function decrypt(string $encryptedData): string
    {
        $info = [
            'iv' => '',
            'tag' => '',
            'add' => '',
        ];
        foreach ($info as &$v) {
            $head = substr($encryptedData, 0, 4);
            $head = unpack('N', $head);
            if (!is_array($head) || !isset($head[1]) || !is_int($head[1]) || $head[1] <= 0) {
                throw new Exception("Decrypt failed");
            }
            $v = substr($encryptedData, 4, $head[1]);
            $encryptedData = substr($encryptedData, 4 + $head[1]);
        }
        $tmp = unpack('a*', $info['add']);
        if (!is_array($tmp) || !isset($tmp[1]) || !is_string($tmp[1])) {
            throw new Exception("Decrypt failed");
        }
        $info['add'] = $tmp[1];
        $ret = openssl_decrypt(
            $encryptedData,
            $this->cipher_algo,
            $this->key,
            OPENSSL_RAW_DATA,
            $info['iv'],
            $info['tag'],
            $info['add']
        );
        if ($ret === false) {
            throw new Exception(openssl_error_string());
        }
        return $ret;
    }
}