#!/usr/bin/env php
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

$clientPharFile = 'client.phar';
$serverPharFile = 'server.phar';
try {
    if (file_exists($serverPharFile)) {
        unlink($serverPharFile);
    }
    if (file_exists($clientPharFile)) {
        unlink($clientPharFile);
    }
    $clientPhar = new Phar($clientPharFile);
    $serverPhar = new Phar($serverPharFile);
    $metadata = [
        'author' => '多情剑客无情剑',
        'version' => '1.0.0',
    ];
    $serverPhar->setMetadata($metadata);
    $clientPhar->setMetadata($metadata);
    $comm = [
        'RSA.php',
        'AES.php',
        'Connection.php',
        'SCParent.php',
        'Config.php',
    ];
    foreach ($comm as $file) {
        $clientPhar->addFile($file);
        $serverPhar->addFile($file);
    }
    $serverPhar->addFile('Server.php');
    $serverPhar->addFile('run_server.php');
    $clientPhar->addFile('Client.php');
    $clientPhar->addFile('run_client.php');
    $serverStub = <<<STUB
<?php
Phar::mapPhar();
require "phar://$serverPharFile/run_server.php";
__HALT_COMPILER();
STUB;
    $clientStub = <<<STUB
<?php
Phar::mapPhar();
require "phar://$clientPharFile/run_client.php";
__HALT_COMPILER();
STUB;
    $serverPhar->setStub($serverStub);
    $clientPhar->setStub($clientStub);
    echo "Phar 文件创建成功: {$serverPharFile}、$clientPharFile" . PHP_EOL;
} catch (Exception $e) {
    echo "创建 Phar 文件失败: " . $e->getMessage() . PHP_EOL;
}