<?php

namespace LaravelSsoClient\Contracts;

use LaravelSsoClient\JWT;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use LaravelSsoClient\Requests\CreateUserRequest;

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
     * Exports (Creates) a user to the single sign-on server.
     *
     * @param CreateUserRequest $request .
     * @return string Exported user identifier.
     */
    public function export(CreateUserRequest $request);

    /**
     * Update the user from SSO server.
     *
     * @param JWT $jwt A JWT token.
     * @param Model $user A user.
     * @return Authenticatable|Model
     */
    public function update(JWT $jwt, Model $user);
}
