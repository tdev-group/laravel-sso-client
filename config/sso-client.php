<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Model
    |--------------------------------------------------------------------------
    |
    | The model to utilize for authentication and importing.
    |
    | This option is only applicable to the DatabaseUserProvider.
    |
    */
    'model' => \App\Models\User::class,

    /*
    |--------------------------------------------------------------------------
    | Authority URL.
    |--------------------------------------------------------------------------
    |
    | The base URL of the authority server.
    |
    */
    'authority' => env('SSO_AUTHORITY'),

    /*
    |--------------------------------------------------------------------------
    | Audience.
    |--------------------------------------------------------------------------
    |
    | Valid audience that will be used to check against the token's audience.
    |
    | If null, validation will be passed.
    |
    */
    'audience' => env('SSO_AUDIENCE', null),

    /*
    |--------------------------------------------------------------------------
    | Time for regular updates.
    |--------------------------------------------------------------------------
    |
    | The time when user data should be updated. In minutes.
    |
    */
    'regular_update' => env('SSO_REGULAR_UPDATE', 120),

    /*
    |--------------------------------------------------------------------------
    | Authority URLS.
    |--------------------------------------------------------------------------
    */
    'urls' => [
        /*
        |--------------------------------------------------------------------------
        | Token endpoint.
        |--------------------------------------------------------------------------
        |
        | Endpoint to retrieve the access token.
        |
        */
        'token' => '/connect/token',

        /*
        |--------------------------------------------------------------------------
        | UserInfo URI.
        |--------------------------------------------------------------------------
        |
        | The uri to get user information.
        |
        */
        'userinfo' => '/connect/userinfo',

        /*
        |--------------------------------------------------------------------------
        | Create user endpoint.
        |--------------------------------------------------------------------------
        |
        | Endpoint for creating a new users on the single sign-on server.  
        |
        */
        'createuser' => '/api/v1/users',

        /*
        |--------------------------------------------------------------------------
        | UserInfo URI.
        |--------------------------------------------------------------------------
        |
        | The uri to get public keys to check JWT token.
        |
        */
        'public_keys' => '/.well-known/openid-configuration/jwks',

        /*
        |--------------------------------------------------------------------------
        | Discovery document URI.
        |--------------------------------------------------------------------------
        |
        | The uri to get information about authority server.
        |
        */
        'discovery_document' => '/.well-known/openid-configuration',
    ],

    /*
    |--------------------------------------------------------------------------
    | Cache settings.
    |--------------------------------------------------------------------------
    */
    'cache' => [
        /*
        |--------------------------------------------------------------------------
        | Cache lifetime.
        |--------------------------------------------------------------------------
        |
        | The short lifetime. Used for cache public keys.
        |
        */
        'lifetime' => 60,

        /*
        |--------------------------------------------------------------------------
        | Cache lifetime.
        |--------------------------------------------------------------------------
        |
        | The long lifetime. Used for cache discovery document.
        |
        */
        'long_lifetime' => 600,
    ],

    /*
    |--------------------------------------------------------------------------
    | Import handlers.
    |--------------------------------------------------------------------------
    |
    | Used for import users from authority server into the local storage.
    |
    */
    'import_handlers' => [
        // ...
    ],

    /*
    |--------------------------------------------------------------------------
    | Client credentials.
    |--------------------------------------------------------------------------
    |
    | Used for client credentials authentication.
    |
    */
    'client_credentials' => [
        /*
        |--------------------------------------------------------------------------
        | Client Id
        |--------------------------------------------------------------------------
        |
        | The client id for client credentials authentication.
        |
        */
        'client_id' => env('SSO_CLIENT_CREDENTIALS_ID'),

        /*
        |--------------------------------------------------------------------------
        | Client Secret
        |--------------------------------------------------------------------------
        |
        | The client secret for client credentials authentication.
        |
        */
        'client_secret' => env('SSO_CLIENT_CREDENTIALS_SECRET'),

        /*
        |--------------------------------------------------------------------------
        | Scope
        |--------------------------------------------------------------------------
        |
        | Sequence of requested scope.
        |
        */
        'scope' => env('SSO_CLIENT_CREDENTIALS_SCOPE'),
    ]
];
