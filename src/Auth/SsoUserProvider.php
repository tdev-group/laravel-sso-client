<?php

namespace LaravelSsoClient\Auth;

use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Hashing\Hasher as HasherContract;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use LaravelSsoClient\Contracts\IUserImporterService;
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
     * Gets a instance of the IUserImporterService.
     *
     * @var IUserImporterService
     */
    protected $userImporter;

    /**
     * Create a new database user provider.
     *
     * @param  \Illuminate\Contracts\Hashing\Hasher  $hasher
     * @param  string  $model
     * @return void
     */
    public function __construct(HasherContract $hasher, $model, IUserImporterService $userImporter, JWT $jwt)
    {
        parent::__construct($hasher, $model);

        $this->jwt = $jwt;
        $this->userImporter = $userImporter;
    }

    /**
     * Retrieve a user by their unique identifier.
     *
     * @param  mixed  $identifier
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function retrieveById($identifier)
    {
        $model = $this->createModel();

        $user = $model->newQuery()
            ->where($this->getIdentifierName($model), $identifier)
            ->first();

        // If the user provider is not returned the user, we should create one.
        if (is_null($user)) {
            $user = $this->userImporter->create($this->jwt);

            // Creates a checkpoint that a user has been imported. 
            $this->createLastUserUpdated($user);
        } else {
            // We need regular update data from sso server.
            $this->updateIfNeedRegularUserUpdate($this->jwt, $user);
        }

        if ($this->hasIdentityClaimsTrait($user)) {
            /** @var \LaravelSsoClient\Traits\IdentityClaims $user */
            $user->setClaims($this->jwt->getClaims());
        }

        return $user;
    }

    private function getIdentifierName($model)
    {
        if (method_exists($model, 'getSsoIdentifierName')) {
            return $model->getSsoIdentifierName();
        }

        return $model->getAuthIdentifierName();
    }


    /**
     * Determine if the user is use the IdentityClaims trait.
     *
     * @param mixed $user
     * @return boolean
     */
    private function hasIdentityClaimsTrait($user)
    {
        return in_array(IdentityClaims::class, class_uses($user), true);
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
        Cache::put($identifier, $identifier, $lifetime);
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
        Cache::remember($identifier, $lifetime, function () use ($jwt, $user,  $identifier) {
            $user = $this->userImporter->update($jwt, $user);

            return $identifier;
        });
    }
}
