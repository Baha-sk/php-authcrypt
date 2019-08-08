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

	public function __construct($payload, Peer $sender, array $recipients)
	{
		$this->base58 = new \StephenHill\Base58();
		$this->payload = $payload;
		$this->sender = $sender;
		$this->recipients = $recipients;
	}

	public function encode()
	{
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

		return [
			'protected' => $headersEncoded,
			'recipients' => $recipients,
			'aad' => $aadEncoded,
			'iv' => Base64Url::encode($nonce),
			'tag' => Base64Url::encode($tag),
			'ciphertext' => Base64Url::encode($ciphertext),
		];
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
				'oid' => Base64Url::encode(\sodium_crypto_box_seal(
					Base64Url::encode($this->sender->getPublicKey()),
					$recipient->getPublicKey()
				)),
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

/*

{
    "protected": base64url({
        "typ": "prs.hyperledger.aries-auth-message",
        "alg": "ECDH+XC20PKW",
        "enc":"XC20P"
    }),
    "recipients": [
        {
            "encrypted_key": "base64url(encrypted CEK)",
            "header": {
                "iv": "base64url(CEK encryption IV)",
                "tag": "base64url(CEK authentication tag)",
            }
        }
    ],
    "aad": "base64url(sha256(concat('.',sort([recipients[0].kid, recipients[n].kid]))))",
}

{
    "protected": "eyJ0eXAiOiJwcnMuaHlwZXJsZWRnZXIuYXJpZXMtYXV0aC1tZXNzYWdlIiwiYWxnIjoiRUNESCtYQzIwUEtXIiwiZW5jIjoiWEMyMFAifQ",
    "recipients": [
        {
            "encrypted_key": "whpkJkvHRP0XX-EqxUOHhHIfuW8i5EMuR3Kxlg5NNIU",
            "header": {
                "kid": "5jMonJACEPcLfqVaz8jpqBLXHHKYgCE71XYBmFXhjZVX",
                "iv": "tjGLK6uChZatAyACFzGmFR4V9othKN8S",
                "tag": "ma9pIjkQuzaqvq_5y5vUlQ",
                "oid": "lalala"
            }
        },
        {
            "encrypted_key": "dDHydlp_wlGt_zwR-yUvESx9fXuO-GRJFGtaw2u6CEw",
            "header": {
                "kid": "TfVVqzPT1FQHdq1CUDe9XYcg6Wu2QMusWKhGBXEZsosg",
                "iv": "7SFlGTxQ4Q2l02D9HRNdFeYQnwntyctb",
                "tag": "9-O6djpNAizix-ZnjAx-Fg",
                "oid": "lalala"
            }
        }
    ],
    "aad": "OGY5ZDIxMDE3YTQ4MTc4YWE5MTk0MWQyOGJmYjQ1ZmZmMTYzYTE3ZjUxYjc4YjA3YTlmY2FlMmMwOTFlMjBhZg",
    "ciphertext": "x1lnQq_pZLgU2ZC4",
    "tag": "2JgOe9SRjJXddT9TyIjqrg",
    "iv": "fDGEXswlWXOBx6FxPC_u6qIuhADnOrW1"
}

*/
