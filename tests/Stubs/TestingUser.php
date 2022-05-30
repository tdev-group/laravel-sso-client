<?php

namespace LaravelSsoClient\Tests\Stubs;

use Illuminate\Foundation\Auth\User;
use LaravelSsoClient\Traits\IdentityClaims;

class TestingUser extends User
{
    use IdentityClaims;
}
