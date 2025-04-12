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
 * 封装socket的类，用于读取和写入数据
 */
class Connection
{
    /**
     * @var null|resource
     */
    protected $conn = null;

    /**
     * @param resource $conn
     */
    public function __construct($conn)
    {
        $this->conn = $conn;
    }

    /**
     * 获取套接字远端名字
     * @return array
     */
    public function getRemoteAddr(): array
    {
        $ret = socket_getpeername($this->conn, $address, $port);
        if ($ret === false) {
            return [];
        }
        return [
            'ip' => $address,
            'port' => $port,
        ];
    }

    /**
     * 获取套接字本地名字
     * @return array|null
     */
    public function getLocalAddr(): ?array
    {
        $ret = socket_getsockname($this->conn, $address, $port);
        if ($ret === false) {
            return null;
        }
        return [
            'ip' => $address,
            'port' => $port,
        ];
    }

    /**
     * @return false|string
     */
    public function read(): false|string
    {
        $message = socket_read($this->conn, 4);
        if ($message === false || $message === '') {
            echo "Could not read input" . PHP_EOL;
            return false;
        }
        $head = unpack('N', $message);
        if (!is_array($head) || !isset($head[1]) || !is_int($head[1]) || $head[1] <= 0) {
            return false;
        }
        $messageLen = $head[1];
        $message = '';
        while (true) {
            $tmp = socket_read($this->conn, $messageLen - strlen($message));
            if ($tmp === false || $tmp === '') {
                echo "Could not read input" . PHP_EOL;
                return false;
            }
            $message .= $tmp;
            if (strlen($message) == $messageLen) {
                break;
            }
        }
        $message = unpack('a*', $message);
        if (!is_array($message) || !isset($message[1]) || !is_string($message[1])) {
            return false;
        }
        return $message[1];
    }

    /**
     * @param string $data
     * @return bool
     */
    public function write(string $data): bool
    {
        $data = pack('a*', $data);
        $message = pack('N', strlen($data)) . $data;
        while (true) {
            $l = socket_write($this->conn, $message, strlen($message));
            if ($l === false) {
                echo "Failed to send data: " . socket_strerror(socket_last_error()) . PHP_EOL;
                return false;
            }
            if ($l === strlen($message)) {
                break;
            }
            $message = substr($message, $l);
        }
        return true;
    }

    public function close(): void
    {
        if (is_resource($this->conn)) {
            socket_close($this->conn);
            $this->conn = null;
        }
    }
}
