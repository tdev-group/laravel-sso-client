<?php

namespace LaravelSsoClient;

use Exception;
use LaravelSsoClient\JWT;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Support\Facades\Log;
use LaravelSsoClient\Exceptions\UnprocessableUserException;

class JWTGuard implements Guard
{
    /**
     * Gets a JWT token.
     *
     * @var JWT
     */
    protected $jwt;

    /**
     * Gets the authenticated user.
     *
     * @var Authenticatable|null
     */
    protected $user;

    /**
     * Gets the request instance.
     *
     * @var Request
     */
    protected $request;

    /**
     * Gets a instance of the user provider.
     *
     * @var UserProvider
     */
    protected $provider;

    /**
     * Create a new authentication guard.
     *
     * @param JWT $jwt
     * @param Request $request
     * @param UserProvider $request
     */
    public function __construct(
        JWT $jwt,
        Request $request,
        UserProvider $provider
    ) {
        $this->jwt = $jwt;
        $this->user = null;
        $this->request = $request;
        $this->provider = $provider;
    }

    /**
     * Determine if the current user is authenticated.
     *
     * @return bool
     */
    public function check()
    {
        return !is_null($this->user());
    }

    /**
     * Determine if the current user is a guest.
     *
     * @return bool
     */
    public function guest()
    {
        return !$this->check();
    }

    /**
     * Get the ID for the currently authenticated user.
     *
     * @return string|null
     */
    public function id()
    {
        if ($user = $this->user()) {
            return $user->getAuthIdentifier();
        }
    }

    /**
     * Determine if the guard has a user instance.
     *
     * @return bool
     */
    public function hasUser()
    {
        return !!$this->user();
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function user()
    {
        if (!is_null($this->user)) {
            return $this->user;
        }

        if ($this->jwt->isValid()) {
            try {
                $user = $this->provider->retrieveById(
                    $this->jwt->getSubject()
                );

                $this->user = $user;
            } catch (UnprocessableUserException $exception) {
                Log::error('Failed to retrieve user from provider', [
                    'exception' => $exception
                ]);

                throw $exception;
            } catch (\Throwable $exception) {
                return null;
            }
        }

        return $this->user;
    }

    /**
     * Validate a user's credentials.
     *
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        throw new Exception('This guard does not support authentication.');
    }

    /**
     * Set the current user.
     *
     * @param  Array $user User info
     * @return void
     */
    public function setUser(Authenticatable $user)
    {
        $this->user = $user;

        return $this;
    }
}
