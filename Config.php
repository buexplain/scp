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
 * 配置类
 */
class Config
{
    public bool $help = false;
    public int $port = 8192;
    public string $host = '127.0.0.1';
    public string $dir = '';
    /**
     * @var string 交换公钥的签名密钥
     */
    public string $password = '54G15oSf5aSn546L';

    protected static self|null $instance = null;

    protected function __construct()
    {
        global $argv;
        foreach ($argv as $arg) {
            if (str_starts_with($arg, '--port=')) {
                $this->port = (int)(trim(substr($arg, strlen('--port='))));
            } elseif (str_starts_with($arg, '--host=')) {
                $this->host = trim(substr($arg, strlen('--host=')));
            } elseif (str_starts_with($arg, '--dir=')) {
                $this->dir = trim(substr($arg, strlen('--dir=')));
            } elseif (str_starts_with($arg, '--password=')) {
                $this->password = trim(substr($arg, strlen('--password=')));
            } elseif (str_starts_with($arg, '--help')) {
                $this->help = true;
            }
        }
        if ($this->dir === '') {
            $this->dir = dirname(str_replace("\\", "/", realpath($argv[0]))) . '/';
        } else {
            $dir = realpath($this->dir);
            if ($dir !== false) {
                $this->dir = $dir;
            }
            $this->dir = str_replace("\\", "/", $this->dir) . '/';
        }
    }

    public function displayHelp(): void
    {
        global $argv;
        $cmd = basename($argv[0]);
        $dirAction = $cmd == 'client.phar' ? 'send' : 'save';
        echo <<<EOT
Usage: php $cmd [options]
Options:
    --port=<port> The port to listen on. Default: 8192
    --host=<host> The host to listen on. Default: 127.0.0.1
    --dir=<dir> The directory to $dirAction. Default: current directory
    --password=<password> Signing key for exchanging public keys.
    --help Display this help message
EOT;
    }

    /**
     * 获取配置
     * @return self
     */
    public static function getInstance(): self
    {
        if (!self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
}