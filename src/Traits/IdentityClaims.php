<?php

namespace LaravelSsoClient\Traits;

use Exception;
use Illuminate\Support\Arr;

trait IdentityClaims
{
    /**
     * Gets the identity claims.
     *
     * @var array
     */
    private $claims = null;

    /**
     * Gets a identity claim by key.
     *
     * @param string $key Any string key.
     * @param mixed $default Default value, that will be returned if key does not exist.
     * @return mixed
     * 
     * @throws UnexpectedValueException If this user has no identity claims.
     */
    public function getClaim(string $key, $default = null)
    {
        return $this->getClaims($key, $default);
    }

    /**
     * Gets the identity claims.
     * If a key was provided returns the specified claim or default if claim with specified key is not found. 
     *
     * @param string|null $key Any string key.
     * @param mixed $default Default value, that will be returned if key does not exist.
     * @return mixed
     * 
     * @throws UnexpectedValueException If this user has no identity claims.
     */
    public function getClaims($key = null, $default = null)
    {
        if (is_null($this->claims)) {
            throw new Exception("This user has no identity claims.");
        }

        return Arr::get($this->claims, $key, $default);
    }

    /**
     * Sets the identity claims.
     *
     * @param array $claims
     * @return void
     */
    public function setClaims(array $claims)
    {
        $this->claims = $claims;
    }
}
