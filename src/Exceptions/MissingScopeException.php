<?php

namespace LaravelSsoClient\Exceptions;

use Illuminate\Auth\Access\AuthorizationException;

class MissingScopeException extends AuthorizationException
{
    /**
     * Get missing scopes.
     *
     * @var array
     */
    protected $scopes;

    /**
     * Create a new missing scope exception.
     *
     * @param  array|string  $scopes
     * @param  string  $message
     * @return void
     */
    public function __construct(array $scopes = [], $message = 'Invalid scope(s) provided.')
    {
        parent::__construct($message);

        $this->scopes = $scopes;
    }

    /**
     * Returns missing scopes.
     *
     * @return array
     */
    public function scopes()
    {
        return $this->scopes;
    }
}
