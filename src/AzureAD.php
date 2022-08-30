<?php

namespace Wishtreehkumar\Azureadsso;

use phpseclib\Crypt\RSA;
use Illuminate\Support\Facades\Http;

/**
 * Clone code from the below library Azure Sample
 * Reason of that is do needfull updates on that as per the laravel 9.
 * https://github.com/Azure-Samples/active-directory-b2c-php-webapp-openidconnect/tree/main-deprecated
 */
class AzureAD
{
    private $aToken;

    private $head;

    private $payload;

    private $clientID;

    private $metadata;

    private $isAuthenticated = false;

    public function construct($token, $type)
    {
        $typeL = strtolower($type);

        $this->clientID = config('azure.client_id');

        $this->metadata = file_get_contents(config("azure.openid_config_{$typeL}"));

        $this->splitIdToken($token);

        if (($this->validateSignature() == true) && ($this->validateClaims() == true)) {
            $this->isAuthenticated =  true;
        } else {
            $this->isAuthenticated =  false;
        }

        return $this;
    }

    public function generateLoginUrl($type)
    {
        $typeL = strtolower($type);

        return config("azure.authz_ept_{$typeL}").'?'.http_build_query(config("azure.authz_ept_{$typeL}_pram"));
    }

    public function generatePassword()
    {
        $symbols = '!@#$%^&*()_+=-';
        $numbers = '0123456789';
        $alphabates = 'abcdefghijklmnopqrstuvwxyz';
        $numbers = '0123456789';

        $symShuffle = substr(str_shuffle($symbols), -4);
        $numShuffle = substr(str_shuffle($numbers), -2);
        $smallAlphaShuffle = substr(str_shuffle($alphabates), -4);
        $capAlphaShuffle = substr(str_shuffle(strtoupper($alphabates)), -2);

        $password = "{$smallAlphaShuffle}{$symShuffle}{$capAlphaShuffle}{$numShuffle}";

        return str_shuffle($password);
    }

    private function getRopcToken()
    {
        $response = Http::asForm()->post(config('azure.token_ept_normal'), [
            'client_id' => config('azure.client_id'),
            'scope' => 'https://graph.microsoft.com/.default',
            'client_secret' => config('azure.client_secret'),
            'grant_type' => 'client_credentials',
        ]);

        return $response->object();
    }

    public function graphApi($method, $endPoint, $body)
    {
        $response = $this->getRopcToken();

        return Http::withToken($response->access_token)->withHeaders([
            'Content-type' => 'application/json',
        ])
        ->$method("https://graph.microsoft.com/v1.0/{$endPoint}", $body);
    }

    public function isAuthenticated()
    {
        return $this->isAuthenticated;
    }

    public function getPayload()
    {
        if ($this->isAuthenticated) {

            return json_decode($this->payload, true);

        }

        return null;
        
    }

    
    private function loadKeysFromAzure($string_microsoftPublicKeyURL) {
        $array_keys = array();

        $jsonString_microsoftPublicKeys = file_get_contents($string_microsoftPublicKeyURL);
        $array_microsoftPublicKeys = json_decode($jsonString_microsoftPublicKeys, true);

        foreach($array_microsoftPublicKeys['keys'] as $array_publicKey) {
            $string_certText = "-----BEGIN CERTIFICATE-----\r\n".chunk_split($array_publicKey['x5c'][0],64)."-----END CERTIFICATE-----\r\n";
            $array_keys[$array_publicKey['kid']] = $this->getPublicKeyFromX5C($string_certText);
        }

        return $array_keys;
    }


    private function getPublicKeyFromX5C($string_certText) {
        $object_cert = openssl_x509_read($string_certText);
        $object_pubkey = openssl_pkey_get_public($object_cert);
        $array_publicKey = openssl_pkey_get_details($object_pubkey);
        return $array_publicKey['key'];
    }

    private function splitIdToken($token)
    {
        // Split the token into Header, Payload, and Signature, and decode
        $this->aToken = explode('.', $token);
        $this->head = base64_decode($this->aToken[0]);
        $this->payload = base64_decode($this->aToken[1]);
    }

    // Converts base64url encoded string into base64 encoded string
    // Also adds the necessary padding to the base64 encoded string
    private function convertBase64urlToBase64($input)
    {
        $padding = strlen($input) % 4;
        if ($padding > 0) {
            $input .= str_repeat('=', 4 - $padding);
        }

        return strtr($input, '-_', '+/');
    }

    private function getJwksUriData()
    {
        $jwks_uri = $this->getClaim('jwks_uri', $this->metadata);

        $key_data = file_get_contents($jwks_uri);

        return $key_data;
    }

    // Validates the RSA signature on the token
    private function validateSignature()
    {
        // Get kid from header
        $kid = $this->getClaim('kid', $this->head);

        // Get private key
        $key_data = $this->getJwksUriData();

        // Extract e and n from the private key
        $e_regex = '/"kid":\W*"' . $kid . '.*"e":\W*"([^"]+)/';
        $e_array = [];
        preg_match($e_regex, $key_data, $e_array);

        $n_regex = '/"kid":\W*"' . $kid . '.*"n":\W*"([^"]+)/';
        $n_array = [];
        preg_match($n_regex, $key_data, $n_array);

        // 'e' and 'n' are base64 URL encoded, change to just base64 encoding
        // $e = $this->convertBase64urlToBase64($e_array[1]);
        $e = $this->convertBase64urlToBase64($e_array[1]);
        // $n = $this->convertBase64urlToBase64($n_array[1]);
        $n = $this->convertBase64urlToBase64($n_array[1]);

        // Convert RSA(e,n) format to PEM format
        $rsa = new RSA;
        $rsa->setPublicKey('<RSAKeyValue>
			<Modulus>' . $n . '</Modulus>
			<Exponent>' . $e . '</Exponent>
			</RSAKeyValue>');
        $public_key = $rsa->getPublicKey();

        // Verify Signature
        $to_verify_data = $this->aToken[0] . '.' . $this->aToken[1];
        $to_verify_sig = base64_decode($this->convertBase64urlToBase64(($this->aToken[2])));

        $verified = openssl_verify($to_verify_data, $to_verify_sig, $public_key, OPENSSL_ALGO_SHA256);

        return $verified;
    }

    // Validate audience, not_before, expiration_time, and issuer claims
    private function validateClaims()
    {
        $audience = $this->getClaim('aud', $this->payload); // Should be app's clientID
        if ($audience != $this->clientID) {
            return false;
        }

        $cur_time = time();
        $not_before = $this->getClaim('nbf', $this->payload); // epoch time, time after which token is valid (so basically nbf < cur time < exp)
        $expiration = $this->getClaim('exp', $this->payload); // epoch time, check that the token is still valid
        if ($not_before > $cur_time) {
            return false;
        }
        if ($cur_time > $expiration) {
            return false;
        }

        // The Issuer Identifier for the OpenID Provider MUST exactly match the value of the iss (issuer) Claim.
        $iss_token = $this->getClaim('iss', $this->payload);
        $iss_metadata = $this->getClaim('issuer', $this->metadata);
        if ($iss_token != $iss_metadata) {
            return false;
        }

        return true;
    }

    private function getClaim($claim, $data)
    {
        $data_array = json_decode($data, true);

        return $data_array[$claim];
    }
}
