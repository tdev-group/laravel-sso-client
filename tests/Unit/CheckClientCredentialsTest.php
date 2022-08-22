<?php

namespace LaravelSsoClient\Tests\Unit;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Foundation\Auth\User;
use LaravelSsoClient\Auth\SsoUserProvider;
use LaravelSsoClient\ClientCredentialsGuard;
use LaravelSsoClient\JWT;
use LaravelSsoClient\JWTGuard;
use LaravelSsoClient\Providers\Middleware\CheckClientCredentials;
use LaravelSsoClient\Tests\Stubs\TestingUser;
use Mockery;
use Mockery\MockInterface;

/**
 * @group unit
 * @group check-client-credentials
 */
class CheckClientCredentialsTest extends TestCase
{
    /** @test */
    public function check_WithValidToken_ShouldReturnedTrue(): void
    {
        // Arrange
        /** @var MockInterface|JWT jwtToken */
        $jwtToken = Mockery::mock(JWT::class);
        $jwtToken->shouldReceive('isValid')->andReturn(true);
        $jwtToken->shouldReceive('getClaims')->andReturn(['token' => 'asdasdasd']);
        $jwtToken->shouldReceive('getScope')->andReturn(['api']);

        $middleware = new CheckClientCredentials($jwtToken);

        // Act
        $result = $middleware->validate(['api']);

        // Assert
        $this->assertTrue($result);
    }

    /**
     * @shouldThrowException
     * @expectedException Illuminate\Auth\AuthenticationException
     */
    public function check_WithInvalidToken_ShouldAuthenticationException(): void
    {
        // Arrange
        /** @var MockInterface|JWT jwtToken */
        $jwtToken = Mockery::mock(JWT::class);
        $jwtToken->shouldReceive('isValid')->andReturn(false);
        $jwtToken->shouldReceive('getClaims')->andReturn(['token' => 'asdasdasd']);
        $jwtToken->shouldReceive('getScope')->andReturn(['api']);

        $middleware = new CheckClientCredentials($jwtToken);

        $this->setExpectedException(AuthenticationException::class);

        // Act
        $middleware->validate(['api']);

        // Assert
        $this->assertException(AuthenticationException::class);
    }
}
