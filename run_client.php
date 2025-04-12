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
        echo "Sending file: $filePath" . PHP_EOL;
        //先做一下md5校验
        $client->write('checkMd5', [
            'to' => $filePath,
            'md5' => md5_file($fileInfo->getPathname()),
        ]);
        $checkMd5 = $client->read();
        if (is_array($checkMd5) && isset($checkMd5['action']) && $checkMd5['action'] === 'checkMd5' && $checkMd5['params']['ok']) {
            continue;
        }
        //md5校验失败，开始发送文件
        $fileObj = new SplFileObject($fileInfo->getPathname());
        $isFirst = true;
        while (!$fileObj->eof()) {
            $tmpFileContent = $fileObj->fread(1024 * 1024);
            if ($tmpFileContent === false) {
                echo "Failed to send file: $filePath" . PHP_EOL;
                exit(1);
            }
            $ok = $client->write('copyFile', [
                'fileContent' => base64_encode($tmpFileContent),
                'to' => $filePath,
                'isFirst' => $isFirst,
                'eof' => $fileObj->eof()
            ]);
            if (!$ok) {
                echo "Failed to send file: $filePath" . PHP_EOL;
                exit(1);
            }
            $isFirst = false;
        }
    }
} catch (Exception $e) {
    echo $e->getMessage() . PHP_EOL;
}

