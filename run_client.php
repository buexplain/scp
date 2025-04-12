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
require_once __DIR__ . '/AES.php';
require_once __DIR__ . '/Connection.php';
require_once __DIR__ . '/Config.php';
require_once __DIR__ . '/SCParent.php';
require_once __DIR__ . '/Client.php';
ini_set("memory_limit", "512M");
set_error_handler(function ($errno, $errStr, $errFile, $errLine) {
});
if (Config::getInstance()->help) {
    Config::getInstance()->displayHelp();
    exit(0);
}
$host = Config::getInstance()->host;
$port = Config::getInstance()->port;
echo "Client is running on $host:$port" . PHP_EOL;
$socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
$result = socket_connect($socket, $host, $port);
if ($result === false) {
    echo "Unable to connect to $host:$port" . PHP_EOL;
    socket_close($socket);
    exit(1);
}
try {
    $client = new Client(new Connection($socket));
    if (!$client->getServerPublicKey()) {
        exit(1);
    }
    if (!$client->sendClientPublicKey()) {
        exit(1);
    }
    if (!$client->getAesKey()) {
        exit(1);
    }
    if (!is_dir(Config::getInstance()->dir)) {
        echo "Dir " . Config::getInstance()->dir . " is not a directory" . PHP_EOL;
        exit(1);
    }
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator(Config::getInstance()->dir),
        RecursiveIteratorIterator::LEAVES_ONLY
    );
    foreach ($iterator as $fileInfo) {
        /**
         * @var SplFileInfo $fileInfo
         */
        if ($fileInfo->isDir()) {
            continue;
        }
        if ($fileInfo->getFilename() === 'client.phar') {
            continue;
        }
        $filePath = str_replace("\\", '/', substr($fileInfo->getPathname(), strlen(Config::getInstance()->dir)));
        //先做一下md5校验
        $fileMd5 = getMd5($client, $filePath);
        if ($fileMd5 && $fileMd5 === md5_file($fileInfo->getPathname())) {
            echo "File $filePath is not changed" . PHP_EOL;
            continue;
        }
        //发送文件
        echo "Sending file: $filePath" . PHP_EOL;
        if (!sendFile($client, $fileInfo->getPathname(), $filePath)) {
            echo "Failed to send file: $filePath" . PHP_EOL;
        }
    }
} catch (Exception $e) {
    echo $e->getMessage() . PHP_EOL;
}

/**
 * 获取文件md5
 * @param Client $client
 * @param string $filePath
 * @return string
 * @throws Exception
 */
function getMd5(Client $client, string $filePath): string
{
    $client->write('getMd5', [
        'filePath' => $filePath,
    ]);
    $fileMd5 = $client->read();
    if (is_array($fileMd5) && $fileMd5['params']['md5']) {
        return (string)($fileMd5['params']['md5']);
    }
    return '';
}

/**
 * 发送文件
 * @param Client $client
 * @param string $file
 * @param string $filePath
 * @return bool
 * @throws Exception
 */
function sendFile(Client $client, string $file, string $filePath): bool
{
    $fileObj = new SplFileObject($file);
    $isFirst = true;
    while (!$fileObj->eof()) {
        $tmpFileContent = $fileObj->fread(1024 * 1024);
        if ($tmpFileContent === false) {
            return false;
        }
        $ok = $client->write('copyFile', [
            'fileContent' => base64_encode($tmpFileContent),
            'to' => $filePath,
            'isFirst' => $isFirst,
            'eof' => $fileObj->eof()
        ]);
        if (!$ok) {
            return false;
        }
        $isFirst = false;
    }
    return true;
}