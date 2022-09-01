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

    private $token;
    private $type;

    private $isAuthenticated = false;

    public function construct($token, $type)
    {
        try {

            $this->token = $token;
            $this->type = strtolower($type);

            $this->clientID = config('azure.client_id');

            $this->metadata = file_get_contents(config("azure.openid_config_{$this->type}"));

            $this->splitIdToken();

            if (($this->validateSignature() == true) && ($this->validateClaims() == true)) {
                $this->isAuthenticated =  true;
            } else {
                $this->isAuthenticated =  false;
            }

        } catch (\Throwable $th) {
            report($th);

            abort(500, $th->getMessage());
        }

        return $this;
    }

    public function generateLoginUrl($type)
    {
        $type = strtolower($type);

        return config("azure.authz_ept_{$type}") . '?' . http_build_query(config("azure.authz_ept_{$type}_pram"));
    }

    public function generatePassword()
    {
        $symbols = '!@#$%^&*()_+=-';
        $numbers = '0123456789';
        $alphabates = 'abcdefghijklmnopqrstuvwxyz';

        $symShuffle = substr(str_shuffle($symbols), -4);
        $numShuffle = substr(str_shuffle($numbers), -2);
        $smallAlphaShuffle = substr(str_shuffle($alphabates), -4);
        $capAlphaShuffle = substr(str_shuffle(strtoupper($alphabates)), -2);

        $password = "{$smallAlphaShuffle}{$symShuffle}{$capAlphaShuffle}{$numShuffle}";

        return str_shuffle($password);
    }

    private function getRopcToken()
    {
        try {
            $response = Http::asForm()->post(config('azure.token_ept_normal'), [
                'client_id' => config('azure.client_id'),
                'scope' => 'https://graph.microsoft.com/.default',
                'client_secret' => config('azure.client_secret'),
                'grant_type' => 'client_credentials',
            ]);

            return $response->object();
        } catch (\Throwable $th) {
            report($th);

            abort(500, $th->getMessage());
        }
    }

    public function graphApi($method, $endPoint, $body = [], $accessToken = null)
    {
        try {
            if (is_null($accessToken)) {
                $response = $this->getRopcToken();
                $accessToken = $response->access_token;
            }

            return Http::withToken($accessToken)->withHeaders([
                'Content-type' => 'application/json',
            ])->$method("https://graph.microsoft.com/v1.0/{$endPoint}", $body);
        } catch (\Throwable $th) {
            report($th);

            abort(500, $th->getMessage());
        }
    }

    public function isAuthenticated()
    {
        return $this->isAuthenticated;
    }

    public function getPayload()
    {
        try {

            if ($this->isAuthenticated) {
                return json_decode($this->payload, true);
            }

            return null;

        } catch (\Throwable $th) {
            report($th);

            abort(500, $th->getMessage());
        }
    }

    private function splitIdToken()
    {
        // Split the token into Header, Payload, and Signature, and decode
        $this->aToken = explode('.', $this->token);
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
        if ($this->type == "normal") {
            return $this->validateSignatureForNormal();
        }

        return $this->validateSignatureForB2C();
    }

    private function base64UrlDecode($arg)
    {
        $res = $arg;
        $res = str_replace('-', '+', $res);
        $res = str_replace('_', '/', $res);
        switch (strlen($res) % 4) {
            case 0:
                break;
            case 2:
                $res .= "==";
                break;
            case 3:
                $res .= "=";
                break;
            default:
                break;
        }
        $res = base64_decode($res);
        return $res;
    }

    private function validateSignatureForB2C()
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

    private function validateSignatureForNormal()
    {
        $token_arr = explode('.', $this->token);
        $headersEnc = $token_arr[0];
        $claimsEnc = $token_arr[1];
        $sigEnc = $token_arr[2];

        // 2 base 64 url decoding
        $headers_arr = json_decode($this->base64UrlDecode($headersEnc), TRUE);
        $claims_arr = json_decode($this->base64UrlDecode($claimsEnc), TRUE);
        $sig = $this->base64UrlDecode($sigEnc);

        // 3 get key list
        $keylist = $this->getJwksUriData();

        $keylist_arr = json_decode($keylist, TRUE);

        // By default token validate flase
        $token_valid = 0;

        foreach ($keylist_arr['keys'] as $key => $value) {

            // 4 select one key
            if ($value['kid'] == $headers_arr['kid']) {

                // 5 get public key from key info
                $cert_txt = '-----BEGIN CERTIFICATE-----' . "\n" . chunk_split($value['x5c'][0], 64) . '-----END CERTIFICATE-----';
                $cert_obj = openssl_x509_read($cert_txt);
                $pkey_obj = openssl_pkey_get_public($cert_obj);
                $pkey_arr = openssl_pkey_get_details($pkey_obj);
                $pkey_txt = $pkey_arr['key'];

                // 6 validate signature
                $token_valid = openssl_verify("{$headersEnc}.{$claimsEnc}", $sig, $pkey_txt, OPENSSL_ALGO_SHA256);
            }
        }

        return $token_valid;
    }

    // Validate audience, notBefore, expiration_time, and issuer claims
    private function validateClaims()
    {
        $audience = $this->getClaim('aud', $this->payload); // Should be app's clientID
        if ($audience != $this->clientID) {
            return false;
        }

        $curTime = time();
        $notBefore = $this->getClaim('nbf', $this->payload); // epoch time, time after which token is valid (so basically nbf < cur time < exp)
        $expiration = $this->getClaim('exp', $this->payload); // epoch time, check that the token is still valid
        if ($notBefore > $curTime) {
            return false;
        }
        if ($curTime > $expiration) {
            return false;
        }

        // The Issuer Identifier for the OpenID Provider MUST exactly match the value of the iss (issuer) Claim.
        $issToken = $this->getClaim('iss', $this->payload);
        $issMetadata = $this->getClaim('issuer', $this->metadata);
        if ($issToken != $issMetadata) {
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
