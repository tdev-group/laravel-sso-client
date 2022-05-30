<?php

namespace LaravelSsoClient\Providers;

use Illuminate\Contracts\Auth\UserProvider;
use LaravelSsoClient\Auth\SsoUserProvider;
use LaravelSsoClient\Contracts\IUserManagerService;
use LaravelSsoClient\Services\SsoService;
use LaravelSsoClient\Services\UserManagerService;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;
use LaravelSsoClient\JWT;
use LaravelSsoClient\JWTGuard;

class SsoServiceProvider extends ServiceProvider
{
    /**
     * Register any authentication / authorization services.
     *
     * @return void
     */
    public function boot()
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../../config/sso-client.php' => config_path('sso-client.php'),
            ], 'sso-client-config');
        }

        Auth::provider('sso-server', function ($app, array $config) {
            $jwt = $app->make(JWT::class);
            $userImporter = $app->make(IUserManagerService::class);

            return new SsoUserProvider($app['hash'], $config['model'], $userImporter, $jwt);
        });

        Auth::extend('jwt', function ($app, string $name, array $config) {
            /** @var Auth $auth */
            $jwt = $app->make(JWT::class);
            $auth = $app->make('auth');

            /** @var UserProvider $userProvider */
            $userProvider = $auth->createUserProvider($config['provider']);

            return new JWTGuard($jwt, $userProvider);
        });
    }

    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        $this->app->singleton(JWT::class, function ($app) {
            return new JWT($app['request']);
        });

        $this->app->singleton(SsoService::class);
        $this->app->singleton(IUserManagerService::class, UserManagerService::class);
    }
}
