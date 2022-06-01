<?php

namespace LaravelSsoClient\Auth;

use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Hashing\Hasher as HasherContract;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use LaravelSsoClient\Contracts\IUserManagerService;
use LaravelSsoClient\Exceptions\UnprocessableUserException;
use LaravelSsoClient\JWT;

class SsoUserProvider extends EloquentUserProvider implements UserProvider
{
    /**
     * Gets a JWT token.
     *
     * @var JWT
     */
    protected $jwt;

    /**
     * Gets a instance of the IUserManagerService.
     *
     * @var IUserManagerService
     */
    protected $userManager;

    /**
     * Create a new database user provider.
     *
     * @param  \Illuminate\Contracts\Hashing\Hasher  $hasher
     * @param  string  $model
     * @return void
     */
    public function __construct(HasherContract $hasher, $model, IUserManagerService $userManager, JWT $jwt)
    {
        parent::__construct($hasher, $model);

        $this->jwt = $jwt;
        $this->userManager = $userManager;
    }

    /**
     * Retrieve a user by their unique identifier.
     *
     * @param  mixed  $identifier
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function retrieveById($identifier)
    {
        /** @var Authenticatable|null $user */
        $user = null;
        $model = $this->createModel();

        if (method_exists($model, 'findUserByIdentifierForSsoClient')) {
            $user = $model->findUserByIdentifierForSsoClient($identifier)->first();
        } else {
            $user = $model->newQuery()
                ->where($model->getAuthIdentifierName(), $identifier)
                ->first();
        }

        if (is_null($user) && method_exists($model, 'correlateUserForSsoClient')) {
            $user = $model->correlateUserForSsoClient(
                $identifier,
                $this->jwt->getClaims()
            )->first();
        }

        return $this->tryImportOrUpdate($user);
    }

    /**
     * Creates a cache point when a user is last updated.
     *
     * @param Authenticatable $user
     */
    private function createLastUserUpdated(Authenticatable $user)
    {
        $lifetime = Config::get('sso-client.regular_update', 120);
        $identifier = $user->getAuthIdentifier();

        // Creates a cache point when a user is last updated. 
        // When the cache point expires, the user data update time comes.
        Cache::put('sso-user-provider:' . $identifier, $identifier, $lifetime);
    }

    /**
     * Update a user data if the user need regular update, and recreate user checkpoint.
     *
     * @param Authenticatable|Model $user
     */
    private function updateIfNeedRegularUserUpdate(JWT $jwt, Authenticatable $user)
    {
        $lifetime = Config::get('sso-client.regular_update', 120);
        $identifier = $user->getAuthIdentifier();

        // If a cache point expires, we update user data. 
        Cache::remember('sso-user-provider:' . $identifier, $lifetime, function () use ($jwt, $user,  $identifier) {
            $user = $this->userManager->update($jwt, $user);

            return $identifier;
        });
    }

    /**
     * Tries to update or import a user from the single sign-on server.
     *
     * @param Authenticatable|null $user
     */
    private function tryImportOrUpdate($user)
    {
        try {
            // If the user provider is not returned the user, we should create one.
            if (is_null($user)) {
                $user = $this->userManager->import($this->jwt);

                // Creates a checkpoint that a user has been imported. 
                $this->createLastUserUpdated($user);
            } else {
                // We need regular update data from sso server.
                $this->updateIfNeedRegularUserUpdate($this->jwt, $user);
            }

            return $user;
        } catch (\Throwable $exception) {
            throw new UnprocessableUserException("Failed to retrieve identity or create one.", 422, $exception);
        }
    }
}
