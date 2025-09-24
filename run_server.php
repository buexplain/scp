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

require_once __DIR__ . '/RSA.php';
require_once __DIR__ . '/AesCbc.php';
require_once __DIR__ . '/AesGcm.php';
require_once __DIR__ . '/Connection.php';
require_once __DIR__ . '/Config.php';
require_once __DIR__ . '/SCParent.php';
require_once __DIR__ . '/Server.php';
ini_set("memory_limit", "512M");
set_error_handler(function ($errno, $errStr, $errFile, $errLine) {
});
if (Config::getInstance()->help) {
    Config::getInstance()->displayHelp();
    exit(0);
}
$host = Config::getInstance()->host;
$port = Config::getInstance()->port;
$socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
socket_bind($socket, $host, $port) or die("Could not bind to port $port" . PHP_EOL);
socket_listen($socket) or die("Could not listen on socket" . PHP_EOL);
echo "Server is running on $host:$port" . PHP_EOL;
while (true) {
    $conn = socket_accept($socket);
    if (!$conn) {
        socket_close($socket);
        echo "Could not accept connection" . PHP_EOL;
        continue;
    }
    if (!socket_set_block($conn)) {
        echo "Could not set socket to blocking" . PHP_EOL;
        socket_close($conn);
        continue;
    }
    $server = new Server(new Connection($conn));
    $credit = false;
    for ($i = 0; $i < 3; $i++) {
        $message = $server->conn->read();
        if ($message === false) {
            break;
        }
        $message = json_decode($message, true);
        echo "Received action: " . $message['action'] . PHP_EOL;
        switch ($message['action']) {
            case 'getServerPublicKey':
                $server->sendServerPublicKey();
                break;
            case
            'setClientPublicKey':
                if ($server->setClientPublicKey($message['clientPublicKey'], $message['timestamp'], $message['sign']) === false) {
                    break 2;
                }
                break;
            case 'getAesKey':
                $server->sendAesKey();
                $credit = true;
                break;
            default:
                echo "Invalid action {$message['action']}" . PHP_EOL;
                break;
        }
    }
    if (!$credit) {
        $server->conn->close();
        echo "Connection closed" . PHP_EOL;
        continue;
    }
    while (true) {
        $message = $server->read();
        if ($message === false) {
            break;
        }
        if ($message === null) {
            continue;
        }
        switch ($message['action']) {
            case 'getMd5':
                getMd5($server, $message['params']['filePath']);
                break;
            case 'copyFile':
                copyFile($message['params']['fileContent'], $message['params']['to'], $message['params']['eof'], $message['params']['isFirst']);
                break;
            default:
                echo "Invalid action {$message['action']}" . PHP_EOL;
                break;
        }
    }
    $server->conn->close();
    echo "Connection closed" . PHP_EOL;
}

/**
 * 获取文件md5
 * @param Server $server
 * @param string $filePath
 * @return void
 * @throws Exception
 */
function getMd5(Server $server, string $filePath): void
{
    $file = Config::getInstance()->dir . ltrim($filePath, '/');
    $server->write('getMd5', [
        'md5' => is_file($file) ? md5_file($file) : '',
    ]);
}

/**
 * 文件复制
 * @param string $fileContent 文件内容
 * @param string $to 保存的路径
 * @param bool $eof 是否结束
 * @param bool $isFirst 是否为第一个块
 * @return void
 */
function copyFile(string $fileContent, string $to, bool $eof, bool $isFirst): void
{
    $to = Config::getInstance()->dir . ltrim($to, '/');
    if ($isFirst) {
        if (!is_dir(dirname($to))) {
            mkdir(dirname($to), 0777, true);
        }
        file_put_contents($to, base64_decode($fileContent));
        if (function_exists('chmod')) {
            @chmod($to, 0666 & ~umask());
        }
    } else {
        file_put_contents($to, base64_decode($fileContent), FILE_APPEND);
    }
    if ($eof) {
        echo "Copy file to $to" . PHP_EOL;
    }
}