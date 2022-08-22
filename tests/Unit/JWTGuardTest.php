<?php

namespace LaravelSsoClient\Tests\Unit;

use Exception;
use Illuminate\Foundation\Auth\User;
use LaravelSsoClient\Auth\SsoUserProvider;
use LaravelSsoClient\JWT;
use LaravelSsoClient\JWTGuard;
use LaravelSsoClient\SsoClaimTypes;
use LaravelSsoClient\Tests\Stubs\TestingUser;
use Mockery;
use Mockery\MockInterface;

/**
 * @group unit
 * @group jwt-guard
 */
class JWTGuardTest extends TestCase
{
    /** @test */
    public function check_WithValidToken_ShouldReturnedTrue(): void
    {
        // Arrange
        /** @var MockInterface|JWT jwtToken */
        $jwtToken = Mockery::mock(JWT::class);
        $jwtToken->shouldReceive('isValid')->andReturn(true);
        $jwtToken->shouldReceive('getSubject')->andReturn(rand());

        /** @var MockInterface|SsoUserProvider jwtToken */
        $userProvider = Mockery::mock(SsoUserProvider::class);
        $userProvider->shouldReceive('retrieveById')->andReturn(new User());

        $jwtGuard = new JWTGuard($jwtToken, $userProvider);

        // Act
        $result = $jwtGuard->check();

        // Assert
        $this->assertTrue($result);
    }

    /** @test */
    public function check_WithInvalidToken_ShouldReturnedFalse(): void
    {
        // Arrange
        /** @var MockInterface|JWT jwtToken */
        $jwtToken = Mockery::mock(JWT::class);
        $jwtToken->shouldReceive('isValid')->andReturn(false);

        /** @var MockInterface|SsoUserProvider jwtToken */
        $userProvider = Mockery::mock(SsoUserProvider::class);

        $jwtGuard = new JWTGuard($jwtToken, $userProvider);

        // Act
        $result = $jwtGuard->check();

        // Assert
        $this->assertFalse($result);
    }

    ///////////////////////////////////////////////////////////////////////

    /** @test */
    public function guest_WithValidToken_ShouldReturnedFalse(): void
    {
        // Arrange
        /** @var MockInterface|JWT jwtToken */
        $jwtToken = Mockery::mock(JWT::class);
        $jwtToken->shouldReceive('isValid')->andReturn(true);
        $jwtToken->shouldReceive('getSubject')->andReturn(rand());

        /** @var MockInterface|SsoUserProvider jwtToken */
        $userProvider = Mockery::mock(SsoUserProvider::class);
        $userProvider->shouldReceive('retrieveById')->andReturn(new User());

        $jwtGuard = new JWTGuard($jwtToken, $userProvider);

        // Act
        $result = $jwtGuard->guest();

        // Assert
        $this->assertFalse($result);
    }

    /** @test */
    public function guest_WithInvalidToken_ShouldReturnedTrue(): void
    {
        // Arrange
        /** @var MockInterface|JWT jwtToken */
        $jwtToken = Mockery::mock(JWT::class);
        $jwtToken->shouldReceive('isValid')->andReturn(false);

        /** @var MockInterface|SsoUserProvider jwtToken */
        $userProvider = Mockery::mock(SsoUserProvider::class);

        $jwtGuard = new JWTGuard($jwtToken, $userProvider);

        // Act
        $result = $jwtGuard->guest();

        // Assert
        $this->assertTrue($result);
    }

    ///////////////////////////////////////////////////////////////////////

    /** @test */
    public function id_WithValidToken_ShouldReturnedUserId(): void
    {
        // Arrange
        $id = rand();
        $user = new User();
        $user->id = $id;

        /** @var MockInterface|JWT jwtToken */
        $jwtToken = Mockery::mock(JWT::class);
        $jwtToken->shouldReceive('isValid')->andReturn(true);
        $jwtToken->shouldReceive('getSubject')->andReturn($id);

        /** @var MockInterface|SsoUserProvider jwtToken */
        $userProvider = Mockery::mock(SsoUserProvider::class);
        $userProvider->shouldReceive('retrieveById')->andReturn($user);

        $jwtGuard = new JWTGuard($jwtToken, $userProvider);

        // Act
        $result = $jwtGuard->id();

        // Assert
        $this->assertEquals($user->id, $result);
    }

    /** @test */
    public function id_WithInvalidToken_ShouldReturnedNull(): void
    {
        // Arrange
        /** @var MockInterface|JWT jwtToken */
        $jwtToken = Mockery::mock(JWT::class);
        $jwtToken->shouldReceive('isValid')->andReturn(false);

        /** @var MockInterface|SsoUserProvider jwtToken */
        $userProvider = Mockery::mock(SsoUserProvider::class);

        $jwtGuard = new JWTGuard($jwtToken, $userProvider);

        // Act
        $result = $jwtGuard->id();

        // Assert
        $this->assertNull($result);
    }

    ///////////////////////////////////////////////////////////////////////

    /** @test */
    public function hasUser_WithValidToken_ShouldReturnedTrue(): void
    {
        // Arrange
        $id = rand();
        $user = new User();
        $user->id = $id;

        /** @var MockInterface|JWT jwtToken */
        $jwtToken = Mockery::mock(JWT::class);
        $jwtToken->shouldReceive('isValid')->andReturn(true);
        $jwtToken->shouldReceive('getSubject')->andReturn($id);

        /** @var MockInterface|SsoUserProvider jwtToken */
        $userProvider = Mockery::mock(SsoUserProvider::class);
        $userProvider->shouldReceive('retrieveById')->andReturn($user);

        $jwtGuard = new JWTGuard($jwtToken, $userProvider);

        // Act
        $result = $jwtGuard->hasUser();

        // Assert
        $this->assertTrue($result);
    }

    /** @test */
    public function hasUser_WithInvalidToken_ShouldReturnedFalse(): void
    {
        // Arrange
        /** @var MockInterface|JWT jwtToken */
        $jwtToken = Mockery::mock(JWT::class);
        $jwtToken->shouldReceive('isValid')->andReturn(false);

        /** @var MockInterface|SsoUserProvider jwtToken */
        $userProvider = Mockery::mock(SsoUserProvider::class);

        $jwtGuard = new JWTGuard($jwtToken, $userProvider);

        // Act
        $result = $jwtGuard->hasUser();

        // Assert
        $this->assertFalse($result);
    }

    ///////////////////////////////////////////////////////////////////////

    /** @test */
    public function user_WithInvalidToken_ShouldReturnedUser(): void
    {
        // Arrange
        $id = rand();
        $user = new User();
        $user->id = $id;

        /** @var MockInterface|JWT jwtToken */
        $jwtToken = Mockery::mock(JWT::class);
        $jwtToken->shouldReceive('isValid')->andReturn(true);
        $jwtToken->shouldReceive('getSubject')->andReturn($id);

        /** @var MockInterface|SsoUserProvider jwtToken */
        $userProvider = Mockery::mock(SsoUserProvider::class);
        $userProvider->shouldReceive('retrieveById')->andReturn($user);

        $jwtGuard = new JWTGuard($jwtToken, $userProvider);

        // Act
        $result = $jwtGuard->user();

        // Assert
        $this->assertEquals($user, $result);
    }

    /** @test */
    public function user_WithInvalidToken_ShouldReturnedNull(): void
    {
        // Arrange
        /** @var MockInterface|JWT jwtToken */
        $jwtToken = Mockery::mock(JWT::class);
        $jwtToken->shouldReceive('isValid')->andReturn(false);

        /** @var MockInterface|SsoUserProvider jwtToken */
        $userProvider = Mockery::mock(SsoUserProvider::class);

        $jwtGuard = new JWTGuard($jwtToken, $userProvider);

        // Act
        $result = $jwtGuard->user();

        // Assert
        $this->assertNull($result);
    }

    /** @test */
    public function getUserClaims_ShouldReturnedUserClaims(): void
    {
        // Arrange
        $id = rand();
        $user = new TestingUser();
        $user->id = $id;

        /** @var MockInterface|JWT jwtToken */
        $jwtToken = Mockery::mock(JWT::class);
        $jwtToken->shouldReceive('isValid')->andReturn(true);
        $jwtToken->shouldReceive('getSubject')->andReturn($id);
        $jwtToken->shouldReceive('getClaims')->andReturn([
            'test' => 1,
            'test_2' => 2
        ]);

        /** @var MockInterface|SsoUserProvider jwtToken */
        $userProvider = Mockery::mock(SsoUserProvider::class);
        $userProvider->shouldReceive('retrieveById')->andReturn($user);

        $jwtGuard = new JWTGuard($jwtToken, $userProvider);

        // Act
        /** @var TestingUser result */
        $result = $jwtGuard->user();

        // Assert
        $this->assertEquals(1, $result->getClaim('test'));
        $this->assertEquals(2, $result->getClaim('test_2'));
        $this->assertIsArray($result->getClaims());
    }
}
