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
 * 服务端
 */
class Server extends SCParent
{
    /**
     * 客户端的公钥
     * @var RSA|null
     */
    protected ?RSA $remoteRsa = null;

    public function __construct(Connection $conn)
    {
        parent::__construct($conn);
        $this->aes = new AesGcm(openssl_random_pseudo_bytes(24));
    }

    /**
     * 发送服务端公钥
     * @return void
     */
    public function sendServerPublicKey(): void
    {
        $timestamp = time();
        $data = $this->conn->getRemoteAddr();
        $data[] = $timestamp;
        $data[] = $this->localRsa->getPublicKey();
        sort($data);
        $sign = hash_hmac(
            'sha256',
            implode($data),
            Config::getInstance()->password
        );
        $this->conn->write(json_encode(array(
            'action' => 'sendServerPublicKey',
            'serverPublicKey' => $this->localRsa->getPublicKey(),
            'timestamp' => $timestamp,
            'sign' => $sign,
        )));
    }

    /**
     * 设置客户端公钥
     * @param $clientPublicKey
     * @param $timestamp
     * @param $sign
     * @return bool
     */
    public function setClientPublicKey($clientPublicKey, $timestamp, $sign): bool
    {
        try {
            $data = $this->conn->getRemoteAddr();
            $data[] = $timestamp;
            $data[] = $clientPublicKey;
            sort($data);
            $currentSign = hash_hmac(
                'sha256',
                implode($data),
                Config::getInstance()->password
            );
            if (!hash_equals($currentSign, $sign)) {
                echo "Invalid client public key sign" . PHP_EOL;
                return false;
            }
            if (abs(time() - $timestamp) > 60) {
                echo "Invalid client public key timestamp" . PHP_EOL;
                return false;
            }
            $this->remoteRsa = new RSA(null, $this->localRsa->decrypt(base64_decode($clientPublicKey)));
        } catch (Exception $e) {
            echo "Failed to decrypt client public key: " . $e->getMessage() . PHP_EOL;
            return false;
        }
        return true;
    }

    /**
     * 发送对称加密密钥
     * @return void
     */
    public function sendAesKey(): void
    {
        try {
            $this->conn->write(json_encode(array(
                'action' => 'sendAesKey',
                'aesKey' => base64_encode($this->remoteRsa->encrypt($this->aes->getKey())),
            )));
        } catch (Exception $e) {
            echo "Failed to encrypt aes key: " . $e->getMessage() . PHP_EOL;
        }
    }
}
