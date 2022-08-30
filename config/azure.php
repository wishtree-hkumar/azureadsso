<?php

return [
    'user_first_name' => env('AZURE_AD_USER_FIRST_NAME', ''),
    'user_last_name' => env('AZURE_AD_USER_LAST_NAME', ''),
    'user_email' => env('AZURE_AD_USER_EMAIL', ''),
    'user_mobile_number' => env('AZURE_AD_USER_MOBILE_NUMBER', ''),

    'client_secret' => env('AZURE_AD_CLIENT_SECRET', ''),
    'client_id' => env('AZURE_AD_CLIENT_ID', ''),
    'tenant_id' => env('AZURE_AD_TENANT_ID', ''),

    'token_ept_normal' => env('AZURE_AD_TOKEN_EPT_NORMAL', ''),

    'authz_ept_normal' => env('AZURE_AD_AUTHZ_EPT_NORMAL', ''),
    'authz_ept_normal_pram' => [
        'client_id' => env('AZURE_AD_CLIENT_ID', ''),
        'response_type' => 'id_token',
        'redirect_uri' => env('AZURE_AD_CALLBACK_URI'.''),
        'response_mode' => 'form_post',
        'nonce' => 'defaultNonce',
        'scope' => 'email profile openid offline_access User.Read',
    ],

    'authz_ept_b2c' => env('AZURE_AD_AUTHZ_EPT_B2C', ''),
    'authz_ept_b2c_pram' => [
        'client_id' => env('AZURE_AD_CLIENT_ID', ''),
        'redirect_uri' => env('AZURE_AD_CALLBACK_URI'.''),
        'nonce' => 'defaultNonce',
        'scope' => 'email profile openid offline_access '.env('AZURE_AD_CLIENT_ID', ''),
        'response_mode' => 'form_post',
        'response_type' => 'id_token',
        'prompt' => 'login',
    ],

    'openid_config_b2c' => env('AZURE_AD_OPENID_CONFIG_B2C', ''),
    'openid_config_normal' => env('AZURE_AD_OPENID_CONFIG_NORMAL', ''),
];
