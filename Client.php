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
 * 客户端
 */
class Client extends SCParent
{
    /**
     * @var string 服务端的公钥
     */
    protected string $serverPublicKey = '';

    /**
     * 获取服务端的公钥
     * @return bool
     */
    public function getServerPublicKey(): bool
    {
        try {
            $this->conn->write(json_encode(array(
                'action' => 'getServerPublicKey',
            )));
            $message = $this->conn->read();
            if ($message === false) {
                echo "Failed to get server public key" . PHP_EOL;
                return false;
            }
            $message = json_decode($message, true);
            if (!is_array($message) || !isset($message['serverPublicKey']) || !is_string($message['serverPublicKey'])) {
                echo "Invalid server public key" . PHP_EOL;
                return false;
            }
            //计算签名
            $timestamp = $message['timestamp'];
            $data = $this->conn->getLocalAddr();
            $data[] = $timestamp;
            $data[] = $message['serverPublicKey'];
            sort($data);
            $sign = hash_hmac(
                'sha256',
                implode($data),
                Config::getInstance()->password
            );
            //验证签名
            if (!hash_equals($sign, $message['sign'])) {
                echo "Invalid server public key sign" . PHP_EOL;
                return false;
            }
            //计算时间戳误差
            $timeDiff = time() - $timestamp;
            if (abs($timeDiff) > 60) {
                echo "Invalid server public key timestamp" . PHP_EOL;
                return false;
            }
            $this->serverPublicKey = $message['serverPublicKey'];
            return true;
        } catch (Exception $e) {
            echo "Failed to get server public key: " . $e->getMessage() . PHP_EOL;
            return false;
        }
    }

    /**
     * 发送客户端公钥
     * @return bool
     */
    public function sendClientPublicKey(): bool
    {
        try {
            $ras = new RSA(null, $this->serverPublicKey);
            $clientPublicKey = base64_encode($ras->encrypt($this->ras->getPublicKey()));
            $timestamp = time();
            $data = $this->conn->getLocalAddr();
            $data[] = $timestamp;
            $data[] = $clientPublicKey;
            sort($data);
            $sign = hash_hmac(
                'sha256',
                implode($data),
                Config::getInstance()->password
            );
            $this->conn->write(json_encode(array(
                'action' => 'setClientPublicKey',
                'clientPublicKey' => $clientPublicKey,
                'timestamp' => $timestamp,
                'sign' => $sign,
            )));
            return true;
        } catch (Exception $e) {
            echo "Failed to encrypt client public key: " . $e->getMessage() . PHP_EOL;
            return false;
        }
    }

    /**
     * 获取对称加密密钥
     * @return bool
     */
    public function getAesKey(): bool
    {
        $this->conn->write(json_encode(array(
            'action' => 'getAesKey',
        )));
        $message = $this->conn->read();
        if ($message === false) {
            echo "Failed to get aes key" . PHP_EOL;
            return false;
        }
        $message = json_decode($message, true);
        if (!is_array($message) || !isset($message['aesKey']) || !is_string($message['aesKey'])) {
            echo "Invalid aes key" . PHP_EOL;
            return false;
        }
        try {
            $this->aes = new AES($this->ras->decrypt(base64_decode($message['aesKey'])));
            return true;
        } catch (Exception $e) {
            echo "Failed to decrypt aes key: " . $e->getMessage() . PHP_EOL;
            return false;
        }
    }
}
