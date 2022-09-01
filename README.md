# Project Description
This package will help you easily implement the Azure Active Directory SSO Login and Graph API Access.

## Installation Steps
----------

    composer require wishtreehkumar/azureadsso

### To edit config file
    php artisan vendor:publish --provider="Wishtreehkumar\Azureadsso\ServiceProvider" --tag="config"

## How to use
----------

### Set .env

    AZURE_AD_CLIENT_SECRET=--
    AZURE_AD_CLIENT_ID=--
    AZURE_AD_TENANT_ID=--

    AZURE_AD_TENANT_NAME=--
    AZURE_AD_POLICY_NAME=--

    AZURE_AD_CALLBACK_URI=--

## Generate Password

    use Wishtreehkumar\Azureadsso\Facades\AzureAD;
    
    $password = AzureAD::generatePassword();

## Generate Login URL

    - There are two type of Azure AD:
        - b2c
        - normal

    $url = AzureAD::generateLoginUrl('b2c');

    return redirect()->away($url);

## Validate id_token in callback url

    $azureAd = AzureAD::construct($request->id_token, 'b2c');

    if ($azureAd->isAuthenticated()) {
        $azurePayload = $azureAd->getPayload();
    }

## Call Graph API

    $grapApi = AzureAD::graphApi($method, $endPoint, $body);

### EG: For create B2C User:

    $dataBody = [
        'accountEnabled' => true,
        'displayName' => "Wishtree Technology",
        'identities' => [
            [
                'signInType' => 'emailAddress',
                'issuer' => 'wtssodemo.onmicrosoft.com',
                'issuerAssignedId' => 'wtemail@mailinator.com',
            ],
        ],
        'passwordProfile' => [
            'password' => $password,
            'forceChangePasswordNextSignIn' => false,
        ],
        'passwordPolicies' => 'DisablePasswordExpiration',
    ];

    $grapApi = AzureAD::graphApi('post', 'users', $dataBody);

    dd($grapApi->object());