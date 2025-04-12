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
 * 双向非对称密钥加密解密类
 */
class RSA
{
    protected null|false|OpenSSLAsymmetricKey $privateKeyRes = null;
    protected null|false|OpenSSLAsymmetricKey $publicKeyRes = null;
    protected string $privateKey = '';
    protected string $publicKey = '';

    /**
     * @param string|null $privateKey 私钥
     * @param string $publicKey 公钥
     * @throws Exception
     */
    public function __construct(?string $privateKey, string $publicKey)
    {
        if (is_string($privateKey)) {
            $this->privateKeyRes = openssl_pkey_get_private($privateKey);
            if (!$this->privateKeyRes) {
                throw new Exception('Failed to load private key: ' . openssl_error_string());
            }
            $this->privateKey = $privateKey;
        }
        $this->publicKeyRes = openssl_pkey_get_public($publicKey);
        if (!$this->publicKeyRes) {
            throw new Exception('Failed to load public key: ' . openssl_error_string());
        }
        $this->publicKey = $publicKey;
    }

    public function __destruct()
    {
        $this->publicKeyRes = null;
        $this->publicKey = '';
        $this->privateKeyRes = null;
        $this->privateKey = '';
    }

    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    /**
     * 加密
     * @param string $data
     * @param int $padding
     * @return string
     * @throws Exception
     */
    public function encrypt(string $data, int $padding = OPENSSL_PKCS1_PADDING): string
    {
        $encrypted = '';
        $dataPieces = str_split($data, $this->getMaxEncryptSize($padding));
        foreach ($dataPieces as $piece) {
            $encryptedPiece = '';
            if (!openssl_public_encrypt($piece, $encryptedPiece, $this->publicKeyRes, $padding)) {
                throw new Exception(openssl_error_string());
            }
            $encrypted .= $encryptedPiece;
        }
        return $encrypted;
    }

    /**
     * 解密
     * @param string $encryptedData
     * @param int $padding
     * @return string
     * @throws Exception
     */
    public function decrypt(string $encryptedData, int $padding = OPENSSL_PKCS1_PADDING): string
    {
        $decrypted = '';
        $dataPieces = str_split($encryptedData, $this->getMaxDecryptSize());
        foreach ($dataPieces as $piece) {
            $decryptedPiece = '';
            if (!openssl_private_decrypt($piece, $decryptedPiece, $this->privateKeyRes, $padding)) {
                throw new Exception(openssl_error_string());
            }
            $decrypted .= $decryptedPiece;
        }
        return $decrypted;
    }

    /**
     * 获取加密的最大长度
     * @param int $padding
     * @return float|int
     * @throws Exception
     */
    protected function getMaxEncryptSize(int $padding): float|int
    {
        $keySize = openssl_pkey_get_details($this->publicKeyRes)['bits'];
        return match ($padding) {
            OPENSSL_PKCS1_PADDING => ($keySize / 8) - 11,
            OPENSSL_NO_PADDING => $keySize / 8,
            OPENSSL_PKCS1_OAEP_PADDING => ($keySize / 8) - 42,
            default => throw new Exception('Unsupported padding'),
        };
    }

    /**
     * 获取解密最大长度
     * @return float|int
     */
    protected function getMaxDecryptSize(): float|int
    {
        return openssl_pkey_get_details($this->privateKeyRes)['bits'] / 8;
    }
}
