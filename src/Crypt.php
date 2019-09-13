<?php

declare(strict_types=1);

namespace gamringer\Aries;

use Jose\Component\Encryption\Algorithm\KeyEncryption\Util\ConcatKDF;
use Base64Url\Base64Url;

class Crypt
{
	protected $base58;
	protected $payload;
	protected $sender;
	protected $recipients;
	protected $output;

	public function __construct($payload, Peer $sender, array $recipients)
	{
		$this->base58 = new \StephenHill\Base58();
		$this->payload = $payload;
		$this->sender = $sender;
		$this->recipients = $recipients;
	}

	public function encode()
	{
		if (isset($this->output)) {
			return $this->output;
		}

		$headers = [
	        "typ" => "prs.hyperledger.aries-auth-message",
	        "alg" => "ECDH-SS+XC20PKW",
	        "enc" => "XC20P",
		];
		$headersEncoded = Base64Url::encode(json_encode($headers));

		$aad = $this->buildAAD();
		$aadEncoded = Base64Url::encode($aad);

		$symaad = $headersEncoded . '.' . $aadEncoded;
		$symkey = \sodium_crypto_aead_xchacha20poly1305_ietf_keygen();
		$nonce = random_bytes(\SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
		$symoutput = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($this->payload, $symaad, $nonce, $symkey);
		$tag = substr($symoutput, -\SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES);
		$ciphertext = substr($symoutput, 0, -\SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES);

		$recipients = $this->encodeRecipients($symkey);

		$this->output = [
			'protected' => $headersEncoded,
			'recipients' => $recipients,
			'aad' => $aadEncoded,
			'iv' => Base64Url::encode($nonce),
			'tag' => Base64Url::encode($tag),
			'ciphertext' => Base64Url::encode($ciphertext),
		];

		return $this->output;
	}

	private function buildAAD()
	{
		$keyids = [];
		foreach ($this->recipients as $recipient) {
			$keyids[] = $this->base58->encode($recipient->getPublicKey());
		}
		sort($keyids);

		return hash('sha256', implode('.', $keyids), true);
	}

	private function encodeRecipients($symkey)
	{
		$output = [];

		foreach ($this->recipients as $recipient) {
			$output[] = $this->encodeRecipient($symkey, $recipient);
		}

		return $output;
	}

	private function encodeRecipient($symkey, Peer $recipient)
	{
		$Z = sodium_crypto_scalarmult($this->sender->getPrivateKey(), $recipient->getPublicKey());
		$apu = Base64Url::encode(random_bytes(64));
		$kek = $this->concatKDF($Z, $apu);
		$nonce = random_bytes(\SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
		$kekoutput = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($symkey, '', $nonce, $kek);
		$tag = substr($kekoutput, -\SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES);
		$ciphertext = substr($kekoutput, 0, -\SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES);
		return [
			'encrypted_key' => Base64Url::encode($ciphertext),
			'header' => [
				'apu' => $apu,
				'iv' => Base64Url::encode($nonce),
				'tag' => Base64Url::encode($tag),
				'kid' => $this->base58->encode($recipient->getPublicKey()),
				'spk' => (new ProtectedJWK(
					$this->sender->getPublicKey(),
					$recipient->getPublicKey()
				))->__toString(),
			]
		];
	}

	private function concatKDF($Z, $apu)
	{
		return ConcatKDF::generate($Z, 'XC20P', 256, $apu);
	}

	public function __toString()
	{
		return json_encode($this->encode());
	}
}
