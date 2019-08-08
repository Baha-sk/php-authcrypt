<?php

declare(strict_types=1);

require_once __DIR__.'/../vendor/autoload.php';

use Base64Url\Base64Url;

$kp = sodium_crypto_box_keypair();
$sender = new \gamringer\Aries\Peer($kp);

$kp = sodium_crypto_box_keypair();
$recipient = new \gamringer\Aries\Peer($kp);

$msg = 'Hello World!';
$jwe = new \gamringer\Aries\Crypt($msg, $sender, [$recipient]);

echo 'Sender SK   : ' . Base64Url::encode($sender->getPrivateKey()), PHP_EOL;
echo 'Sender PK   : ' . Base64Url::encode($sender->getPublicKey()), PHP_EOL;
echo 'Recipient SK: ' . Base64Url::encode($recipient->getPrivateKey()), PHP_EOL;
echo 'Recipient PK: ' . Base64Url::encode($recipient->getPublicKey()), PHP_EOL;
echo 'Payload     : ' . Base64Url::encode($msg), PHP_EOL;
echo '--------------------------------', PHP_EOL;
echo $jwe, PHP_EOL;
echo '--------------------------------', PHP_EOL;
echo json_encode($jwe->encode(), \JSON_PRETTY_PRINT), PHP_EOL;
