<?php
return [
    'client_secret' => env('AZURE_AD_CLIENT_SECRET', ''),
    'client_id' => env('AZURE_AD_CLIENT_ID', ''),
    'tenant_id' => env('AZURE_AD_TENANT_ID', ''),

    'token_ept_normal' => "https://login.microsoftonline.com/".env('AZURE_AD_TENANT_ID')."/oauth2/v2.0/token",

    'authz_ept_normal' => "https://login.microsoftonline.com/".env('AZURE_AD_TENANT_ID')."/oauth2/v2.0/authorize",
    'authz_ept_normal_pram' => [
        'client_id' => env('AZURE_AD_CLIENT_ID', ''),
        'response_type' => 'id_token',
        'redirect_uri' => env('AZURE_AD_CALLBACK_URI'.''),
        'response_mode' => 'form_post',
        'nonce' => 'defaultNonce',
        'scope' => 'email profile openid offline_access User.Read',
    ],

    'authz_ept_b2c' => "https://".env('AZURE_AD_TENANT_NAME').".b2clogin.com/".env('AZURE_AD_TENANT_NAME').".onmicrosoft.com/".env('AZURE_AD_POLICY_NAME')."/oauth2/v2.0/authorize",

    'authz_ept_b2c_pram' => [
        'client_id' => env('AZURE_AD_CLIENT_ID', ''),
        'redirect_uri' => env('AZURE_AD_CALLBACK_URI'.''),
        'nonce' => 'defaultNonce',
        'scope' => 'email profile openid offline_access '.env('AZURE_AD_CLIENT_ID', ''),
        'response_mode' => 'form_post',
        'response_type' => 'id_token',
        'prompt' => 'login',
    ],

    'openid_config_b2c' => "https://".env('AZURE_AD_TENANT_NAME').".b2clogin.com/".env('AZURE_AD_TENANT_NAME').".onmicrosoft.com/".env('AZURE_AD_POLICY_NAME')."/v2.0/.well-known/openid-configuration",

    'openid_config_normal' => "https://login.microsoftonline.com/".env('AZURE_AD_TENANT_ID')."/v2.0/.well-known/openid-configuration",
];
