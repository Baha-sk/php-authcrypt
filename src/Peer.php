<?php

declare(strict_types=1);

namespace gamringer\Aries;

class Peer
{
	protected $publicKey;
	protected $privateKey;

	public function __construct($kp)
	{
		$this->publicKey = \sodium_crypto_box_publickey($kp);
		$this->privateKey = \sodium_crypto_box_secretkey($kp);
	}

	public function getPublicKey()
	{
		return $this->publicKey;
	}

	public function getPrivateKey()
	{
		return $this->privateKey;
	}
}
