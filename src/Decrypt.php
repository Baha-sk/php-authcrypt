<?php

declare(strict_types=1);

namespace gamringer\Aries;

use Jose\Component\Encryption\Algorithm\KeyEncryption\Util\ConcatKDF;
use Base64Url\Base64Url;

class Decrypt
{
	protected $base58;
	protected $recipient;

	public function __construct(Peer $recipient)
	{
		$this->base58 = new \StephenHill\Base58();
		$this->recipient = $recipient;
	}

	public function decrypt($jwe, Peer $sender)
	{
		$authcrypt = json_decode($jwe, true);
		if (json_last_error() !== JSON_ERROR_NONE) {
			throw new \Exception('Not valid JSON');
		}

		$jsonHeaders = Base64Url::decode($authcrypt['protected']);
		$headers = json_decode($jsonHeaders, true);
		if (json_last_error() !== JSON_ERROR_NONE) {
			throw new \Exception('Not valid JSON');
		}

		if ($headers['typ'] != 'prs.hyperledger.aries-auth-message') {
			throw new \Exception('Invalid JWE type');
		}

		if ($headers['alg'] != 'ECDH-SS+XC20PKW') {
			throw new \Exception('Invalid JWE alg');
		}

		if ($headers['enc'] != 'XC20P') {
			throw new \Exception('Invalid JWE enc');
		}

		$mykid = $this->base58->encode($this->recipient->getPublicKey());
		$myrecipient = null;
		foreach ($authcrypt['recipients'] as $recipient) {
			if ($recipient['header']['kid'] == $mykid) {
				$myrecipient = $recipient;
				break;
			}
		}
		if ($myrecipient === null) {
			throw new \Exception('Payload not intended for recipient.');
		}
		$senderkid = \sodium_crypto_box_seal_open(
			Base64Url::decode($myrecipient['header']['oid']),
			sodium_crypto_box_keypair_from_secretkey_and_publickey(
				$this->recipient->getPrivateKey(),
				$this->recipient->getPublicKey()
			)
		);
		if ($senderkid != $this->base58->encode($sender->getPublicKey())) {
			throw new \Exception('Payload not sent by expected sender.');
		}

		$Z = sodium_crypto_scalarmult($this->recipient->getPrivateKey(), $sender->getPublicKey());
		$kek = $this->concatKDF($Z, $myrecipient['header']['apu']);
		$nonce = Base64Url::decode($myrecipient['header']['iv']);
		$cekPayload = Base64Url::decode($myrecipient['encrypted_key']).Base64Url::decode($myrecipient['header']['tag']);
		$cek = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($cekPayload, '', $nonce, $kek);
		if ($cek === false) {
			throw new \Exception('Invalid Authcrypt');
		}

		$aad = $authcrypt['protected'] . '.' . $authcrypt['aad'];

		$contentPayload = Base64Url::decode($authcrypt['ciphertext']).Base64Url::decode($authcrypt['tag']);
		$plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
			$contentPayload,
			$aad,
			Base64Url::decode($authcrypt['iv']),
			$cek
		);
		if ($plaintext === false) {
			throw new \Exception('Invalid Authcrypt');
		}

		return $plaintext;
	}

	private function concatKDF($Z, $apu)
	{
		return ConcatKDF::generate($Z, 'XC20P', 256, $apu);
	}
}
