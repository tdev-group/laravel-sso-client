<?php

namespace LaravelSsoClient\Contracts;

use LaravelSsoClient\JWT;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;

interface IUserManagerService
{
    /**
     * Creates a new user.
     *
     * @param JWT $jwt A JWT token.
     * @return Authenticatable|Model
     */
    public function import(JWT $jwt);

    /**
     * Update the user from SSO server.
     *
     * @param JWT $jwt A JWT token.
     * @param Model $user A user.
     * @return Authenticatable|Model
     */
    public function update(JWT $jwt, Model $user);
}
