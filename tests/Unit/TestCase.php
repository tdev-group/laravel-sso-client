<?php

namespace LaravelSsoClient\Tests\Unit;

use Firebase\JWT\JWT;
use Illuminate\Http\Request;
use LaravelSsoClient\SsoClaimTypes;
use Mockery;

class TestCase extends \Orchestra\Testbench\TestCase
{
    public const KEY = "oKFdeWr3Ie8olbbPTJZa6CFe2Bis";

    public function tearDown(): void
    {
        Mockery::close();
    }

    /**
     * Creates a new request instance with JWT token if the token was provided.
     *
     * @param string|null $token
     * @return Request
     */
    public function makeRequest($token = null)
    {
        /** @var \Mockery\MockInterface $request */
        $request = Mockery::mock(Request::class);

        $request->shouldReceive('header')->withArgs(['Authorization'])->andReturn($token);

        return $request;
    }

    public function getToken($claims = [])
    {
        $claims = array_merge([
            SsoClaimTypes::SUBJECT => rand(0, 100000)
        ], $claims);

        return JWT::encode($claims, self::KEY);
    }

    public function getBearerToken($token = null)
    {
        $token = $token ?? $this->getToken();

        return 'Bearer ' . $token;
    }
}
