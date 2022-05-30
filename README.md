# Introduction

The LaravelSsoClient package is meant to provide you an opportunity to easily authenticate users using OpenID Connect protocol.

# Installation

To install this package you will need:

- Laravel 5.6 +
- PHP 7.1 +

Or

- Laravel 8.0 +
- PHP 8.0 +

Use composer to install

```
composer require tdev-group/laravel-sso-client:1.0.0
```

Open `config/app.php` and register the required service providers above your application providers.

```
'providers' => [
    ...
    LaravelSsoClient\Providers\SsoServiceProvider::class
    ...
]
```

After that, you need to publish the configuration using the following Artisan command:

```
php artisan vendor:publish --tag="sso-client-config"
```

And Last you need, open `config/auth.php` and add following user provider and `sso` guard.

```
'guards' => [
    ...
    'sso' => [
        'driver' => 'sso',
        'provider' => 'sso-server',
    ],
    ...
],
'providers' => [
    ...
    'sso-server' => [
        'driver' => 'sso-server',
        'model' => App\Models\Account::class,
    ],
    ...
],
```

register `sso` guard in the same file.

# Usage

To protect your routes, use the following construction:

```
Route::middleware('auth:sso')->get('/protected', function (Illuminate\Http\Request $request) {
    return "You are on protected zone";
});
```

# Advance Usage

If you need another field for `user id` to correlate a user with the users from the sso service, add the following method to your `User` model.

```
class User extends Authenticatable
{
    /**
     * Gets the sso identifier name.
     *
     * @return string
     */
    public function getSsoIdentifierName()
    {
        return 'sso_user_id';
    }
}

```
