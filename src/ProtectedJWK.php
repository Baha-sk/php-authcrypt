<?php

declare(strict_types=1);

namespace gamringer\Aries;

use Jose\Component\Encryption\Algorithm\KeyEncryption\Util\ConcatKDF;
use Base64Url\Base64Url;

class ProtectedJWK
{
	protected $base58;
	protected $senderKey;
	protected $recipientKey;

	public function __construct($senderKey, $recipientKey)
	{
		$this->base58 = new \StephenHill\Base58();
		$this->senderKey = $senderKey;
		$this->recipientKey = $recipientKey;
	}

	public function encode()
	{
		/*
		{
		  "iv": "WhTjm6-C_lbNT8Cds7g_67Lg6JHAw5NA",
		  "epk": {
		    "kty": "OKP",
		    "crv": "X25519",
		    "x": "g64_nRRHT2bMI_XcOWGE7I8gPqMUY1xiCnobt-XCRCY"
		  },
		  "typ": "jose",
		  "cty": "jwk+json",
		  "alg": "ECDH-ES+XC20PKW",
		  "enc": "XC20P"
		}
		*/
		$ekp = sodium_crypto_box_keypair();
		$epk = \sodium_crypto_box_publickey($ekp);
		$esk = \sodium_crypto_box_secretkey($ekp);

		$pnonce = random_bytes(\SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
		$symkey = \sodium_crypto_aead_xchacha20poly1305_ietf_keygen();

		list($knonce, $encryptedKey, $ktag) = $this->encryptKey($epk, $symkey);

		$headers = [
	        "typ" => "jose",
	        "cty" => "jwk+json",
	        "alg" => "ECDH-ES+XC20PKW",
	        "enc" => "XC20P",
	        "epk" => [
	        	"kty" => "OKP",
	        	"crv" => "X25519",
	        	"x" => Base64Url::encode($epk),
	        ],
	        "iv" => Base64Url::encode($knonce),
	        "tag" => Base64Url::encode($ktag),
		];

		$payload = json_encode([
        	"kty" => "OKP",
        	"crv" => "X25519",
        	"x" => Base64Url::encode($this->senderKey),
        ]);

		$headersEncoded = Base64Url::encode(json_encode($headers));

		$nonce = random_bytes(\SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
		$symoutput = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($payload, $headersEncoded, $nonce, $symkey);
		$tag = substr($symoutput, -\SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES);
		$ciphertext = substr($symoutput, 0, -\SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES);



		return [
			$headersEncoded,
			Base64Url::encode($encryptedKey),
			Base64Url::encode($nonce),
			Base64Url::encode($ciphertext),
			Base64Url::encode($tag),
		];
	}

	private function encryptKey($epk, $symkey)
	{
		$Z = sodium_crypto_scalarmult($epk, $this->recipientKey);
		$kek = $this->concatKDF($Z);
		$nonce = random_bytes(\SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
		$kekoutput = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($symkey, '', $nonce, $kek);
		$tag = substr($kekoutput, -\SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES);
		$ciphertext = substr($kekoutput, 0, -\SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES);
		return [
			$nonce,
			$ciphertext,
			$tag,
		];
	}

	private function concatKDF($Z)
	{
		return ConcatKDF::generate($Z, 'XC20PKW', 256);
	}

	public function __toString()
	{
		return implode('.', $this->encode());
	}
}
