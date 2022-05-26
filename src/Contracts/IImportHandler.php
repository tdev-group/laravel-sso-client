<?php

namespace LaravelSsoClient\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;

interface IImportHandler
{
    /**
     * Handler user imports.
     *
     * @param Model $user An new user model.
     * @param array $claims The list of the user claims. 
     * @param array $userinfo The user information.
     * @return Model The user model for chaining.
     */
    public function handle(Model $user, array $claims, array $userinfo);
}
