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
 * 服务端和客户端通信的父类
 */
class SCParent
{
    /**
     * socket 连接
     * @var null|Connection
     */
    public ?Connection $conn = null;
    /**
     * RSA 加密解密类
     * @var null|RSA
     */
    protected ?RSA $localRsa = null;
    /**
     * AES 加密解密类
     * @var AesGcm|null
     */
    public ?AesGcm $aes = null;

    /**
     * @param Connection $connection
     * @throws Exception
     */
    public function __construct(Connection $connection)
    {
        $this->conn = $connection;
        $config = array(
            "private_key_bits" => 2048, // 密钥长度
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        );
        $res = openssl_pkey_new($config);
        if (!$res) {
            throw new Exception("Failed to create rsa key: " . openssl_error_string());
        }
        $privateKey = '';
        openssl_pkey_export($res, $privateKey);
        $publicKeyDetails = openssl_pkey_get_details($res);
        $this->localRsa = new RSA($privateKey, $publicKeyDetails['key']);
    }

    /**
     * 读取消息
     * @return array|false|null array是正常的消息，false是断开连接，null是消息格式错误
     * @throws Exception
     */
    public function read(): false|array|null
    {
        $message = $this->conn->read();
        if ($message === false) {
            return false;
        }
        $message = json_decode($this->aes->decrypt($message), true);
        if (!is_array($message) || !isset($message['action']) || !is_string($message['action'])) {
            echo "Invalid message" . PHP_EOL;
            return null;
        }
        return $message;
    }

    /**
     * 发送消息
     * @param string $action 操作
     * @param mixed $params 参数
     * @return bool
     * @throws Exception
     */
    public function write(string $action, mixed $params): bool
    {
        $data = json_encode(array(
            'action' => $action,
            'params' => $params,
        ));
        $add = [
            time(),
        ];
        $add = array_merge($add, $this->conn->getLocalAddr());
        $add = array_merge($add, $this->conn->getRemoteAddr());
        $add = sha1(implode('|', $add));
        return $this->conn->write($this->aes->encrypt($data, $add));
    }
}