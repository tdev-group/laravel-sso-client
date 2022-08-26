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
composer require tdev-group/laravel-sso-client:^1.2.5
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

# Import Users

To import users from the single sign-on server into local database you need to create `UserImportHandler`.

```
namespace App\Handlers;

use App\Models\User;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Arr;
use LaravelSsoClient\Contracts\IImportHandler;
use LaravelSsoClient\SsoClaimTypes;

class AccountImportHandler implements IImportHandler
{
    /**
     * Handler user imports.
     *
     * @param User|Model $user An new user model.
     * @param array $claims The list of the user claims.
     * @param array $userinfo The user information.
     * @return Model The user model for chaining.
     */
    public function handle(Model $user, array $claims, array $userinfo)
    {
        $user->guid = Arr::get($userinfo, SsoClaimTypes::SUBJECT, $user->guid);
        $user->email = Arr::get($userinfo, SsoClaimTypes::EMAIL, $user->email);
        $user->fullName = Arr::get($userinfo, SsoClaimTypes::NAME, $user->fullName);
        $user->displayName = Arr::get($userinfo, SsoClaimTypes::NAME, $user->displayName)

        return $user;
    }
```

Don't forget to register a handler in `sso-server.php ` file.

```
'import_handlers' => [
    ...
    AccountImportHandler::class
],
```

# Users Correlations

If your users already have a database identifier and you want to define another property for the identifier from single sign-on server, you can do this by simply adding the following methods to your `User` model.

```
class User extends Authenticatable
{
    /**
     * Finds a user by identifier from single sign-on server.
     *
     * @return \Illuminate\Database\Eloquent\Builder
     */
    public function findUserByIdentifierForSsoClient($subject)
    {
        return $this->where('guid', $subject);
    }

    /**
     * Correlates users from the single sign-on server with the database users.
     *
     * @return \Illuminate\Database\Eloquent\Builder
     */
    public function correlateUserForSsoClient($identifier, $claims, $userInfo)
    {
        // return $this->where('guid', $identifier);

        return $this->where('email', $userInfo[SsoClaimTypes::Email])->where(...);
    }
}
```

# Client Credentials

To use client credentials authorisation you need, open `app/Http/Kernel.php` and add client route middleware.

```
$routeMiddleware = [
    ...
    'sso-client' => \LaravelSsoClient\Providers\Middleware\CheckClientCredentials::class
    ...
],
```

If you want to use route scopes then you need to add scope in your route middleware

```
Route::middleware('sso-client:scope')->get('/protected', function (Illuminate\Http\Request $request) {
    return "You are on protected zone";
});
```
