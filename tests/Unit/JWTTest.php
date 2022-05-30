<?php

namespace LaravelSsoClient\Tests\Unit;

use Exception;
use LaravelSsoClient\JWT;
use LaravelSsoClient\SsoClaimTypes;
use Mockery;
use Mockery\MockInterface;
use UnexpectedValueException;

class JWTTest extends TestCase
{
    /** @test */
    public function getToken_WithBearerToken_ShouldReturnedToken(): void
    {
        // Arrange
        $token = $this->getToken();
        $bearer = $this->getBearerToken($token);
        $jwtToken = new JWT($this->makeRequest($bearer));

        // Act 
        $result = $jwtToken->getToken();

        // Assert
        $this->assertEquals($token, $result);
    }

    /** @test */
    public function getToken_WithoutToken_ShouldThrowAnException(): void
    {
        // Arrange
        $jwtToken = new JWT($this->makeRequest());

        // Assert
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Authorization header is empty.');

        // Act 
        $jwtToken->getToken();
    }

    /** @test */
    public function getToken_WithNotBearerToken_ShouldThrowAnException(): void
    {
        // Arrange
        $token = 'AnotherTokenType ' . $this->getToken();
        $jwtToken = new JWT($this->makeRequest($token));

        // Assert
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Invalid authorization token. (Not Bearer token)');

        // Act 
        $jwtToken->getToken();
    }

    /** @test */
    public function getToken_WithBearerPrefix_ShouldThrowAnException(): void
    {
        // Arrange
        $token = 'Bearer ';
        $jwtToken = new JWT($this->makeRequest($token));

        // Assert
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Invalid authorization token.');

        // Act 
        $jwtToken->getToken();
    }

    ///////////////////////////////////////////////////////////////////////

    /** @test */
    public function getAuthorizationHeader_WithBearerToken_ShouldReturnToken(): void
    {
        // Arrange
        $token = $this->getToken();
        $bearer = $this->getBearerToken($token);
        $jwtToken = new JWT($this->makeRequest($bearer));

        // Act 
        $result = $jwtToken->getAuthorizationHeader();

        // Assert
        $this->assertEquals($bearer, $result);
    }

    /** @test */
    public function getAuthorizationHeader_WithoutToken_ShouldThrowAnException(): void
    {
        // Arrange
        $jwtToken = new JWT($this->makeRequest());

        // Assert
        $this->expectException(UnexpectedValueException::class);
        $this->expectExceptionMessage('Authorization header is empty.');

        // Act 
        $jwtToken->getToken();
    }

    ///////////////////////////////////////////////////////////////////////

    /** @test */
    public function validAudience_WithNormalToken_ShouldReturnedTrue(): void
    {
        // Arrange
        $audience = "https://sso.talan.group";
        $token = $this->getToken();

        /** @var MockInterface|JWT jwtToken */
        $jwtToken = Mockery::mock(JWT::class);
        $jwtToken->makePartial();
        $jwtToken->shouldReceive('decode')->andReturn([
            SsoClaimTypes::AUDIENCE => $audience
        ]);
        $jwtToken->shouldReceive('getToken')->andReturn($token);

        $this->app['config']->set('sso-client.audience', $audience);

        // Act 
        $result = $jwtToken->validAudience();

        // Assert
        $this->assertTrue($result);
    }

    /** @test */
    public function validAudience_WithAnotherAudience_ShouldReturnedFalse(): void
    {
        // Arrange
        $audience = "https://sso.talan.group";
        $token = $this->getToken();

        /** @var MockInterface|JWT jwtToken */
        $jwtToken = Mockery::mock(JWT::class);
        $jwtToken->makePartial();
        $jwtToken->shouldReceive('decode')->andReturn([
            SsoClaimTypes::AUDIENCE => "https://another-sso.talan.group"
        ]);
        $jwtToken->shouldReceive('getToken')->andReturn($token);

        $this->app['config']->set('sso-client.audience', $audience);

        // Act 
        $result = $jwtToken->validAudience();

        // Assert
        $this->assertFalse($result);
    }

    /** @test */
    public function validAudience_WithoutClaim_ShouldReturnedFalse(): void
    {
        // Arrange
        $audience = "https://sso.talan.group";
        $token = $this->getToken();

        /** @var MockInterface|JWT jwtToken */
        $jwtToken = Mockery::mock(JWT::class);
        $jwtToken->makePartial();
        $jwtToken->shouldReceive('decode')->andReturn([]);
        $jwtToken->shouldReceive('getToken')->andReturn($token);

        $this->app['config']->set('sso-client.audience', $audience);

        // Act 
        $result = $jwtToken->validAudience();

        // Assert
        $this->assertFalse($result);
    }

    /** @test */
    public function validAudience_WithBrokenToken_ShouldReturnedFalse(): void
    {
        // Arrange
        $audience = "https://sso.talan.group";

        /** @var MockInterface|JWT jwtToken */
        $jwtToken = Mockery::mock(JWT::class);
        $jwtToken->makePartial();
        $jwtToken->shouldReceive('decode')->andReturn([
            SsoClaimTypes::AUDIENCE => $audience,
        ]);
        $jwtToken->shouldReceive('getToken')->andThrow(Exception::class);

        $this->app['config']->set('sso-client.audience', $audience);

        // Act 
        $result = $jwtToken->validAudience();

        // Assert
        $this->assertFalse($result);
    }

    ///////////////////////////////////////////////////////////////////////

    /** @test */
    public function validIssuer_WithNormalToken_ShouldReturnedTrue(): void
    {
        // Arrange
        $issuer = "https://sso.talan.group";
        $token = $this->getToken();

        /** @var MockInterface|JWT jwtToken */
        $jwtToken = Mockery::mock(JWT::class);
        $jwtToken->makePartial();
        $jwtToken->shouldReceive('decode')->andReturn([
            SsoClaimTypes::ISSUER => $issuer
        ]);
        $jwtToken->shouldReceive('getToken')->andReturn($token);

        $this->app['config']->set('sso-client.authority', $issuer);

        // Act 
        $result = $jwtToken->validIssuer();

        // Assert
        $this->assertTrue($result);
    }

    /** @test */
    public function validIssuer_WithAnotherAudience_ShouldReturnedFalse(): void
    {
        // Arrange
        $issuer = "https://sso.talan.group";
        $token = $this->getToken();

        /** @var MockInterface|JWT jwtToken */
        $jwtToken = Mockery::mock(JWT::class);
        $jwtToken->makePartial();
        $jwtToken->shouldReceive('decode')->andReturn([
            SsoClaimTypes::ISSUER => "https://another-sso.talan.group"
        ]);
        $jwtToken->shouldReceive('getToken')->andReturn($token);

        $this->app['config']->set('sso-client.authority', $issuer);

        // Act 
        $result = $jwtToken->validIssuer();

        // Assert
        $this->assertFalse($result);
    }

    /** @test */
    public function validIssuer_WithoutClaim_ShouldReturnedFalse(): void
    {
        // Arrange
        $issuer = "https://sso.talan.group";
        $token = $this->getToken();

        /** @var MockInterface|JWT jwtToken */
        $jwtToken = Mockery::mock(JWT::class);
        $jwtToken->makePartial();
        $jwtToken->shouldReceive('decode')->andReturn([]);
        $jwtToken->shouldReceive('getToken')->andReturn($token);

        $this->app['config']->set('sso-client.authority', $issuer);

        // Act 
        $result = $jwtToken->validIssuer();

        // Assert
        $this->assertFalse($result);
    }

    /** @test */
    public function validIssuer_WithBrokenToken_ShouldReturnedFalse(): void
    {
        // Arrange
        $issuer = "https://sso.talan.group";

        /** @var MockInterface|JWT jwtToken */
        $jwtToken = Mockery::mock(JWT::class);
        $jwtToken->makePartial();
        $jwtToken->shouldReceive('decode')->andReturn([
            SsoClaimTypes::ISSUER => $issuer,
        ]);
        $jwtToken->shouldReceive('getToken')->andThrow(Exception::class);

        $this->app['config']->set('sso-client.authority', $issuer);

        // Act 
        $result = $jwtToken->validIssuer();

        // Assert
        $this->assertFalse($result);
    }

    ///////////////////////////////////////////////////////////////////////

    /** @test */
    public function isValid_WithNormalToken_ShouldReturnedTrue(): void
    {
        // Arrange
        $audience = "https://sso.talan.group";
        $authority = "https://sso.talan.group";
        $token = $this->getToken();

        /** @var MockInterface|JWT jwtToken */
        $jwtToken = Mockery::mock(JWT::class);
        $jwtToken->makePartial();
        $jwtToken->shouldReceive('decode')->andReturn([
            SsoClaimTypes::ISSUER => $authority,
            SsoClaimTypes::AUDIENCE => $audience,
        ]);
        $jwtToken->shouldReceive('getToken')->andReturn($token);

        $this->app['config']->set('sso-client.audience', $audience);
        $this->app['config']->set('sso-client.authority', $authority);

        // Act 
        $result = $jwtToken->isValid();

        // Assert
        $this->assertTrue($result);
    }

    /** @test */
    public function isValid_WithoutAudience_ShouldReturnedTrue(): void
    {
        // Arrange
        $audience = "https://sso.talan.group";
        $authority = "https://sso.talan.group";
        $token = $this->getToken();

        /** @var MockInterface|JWT jwtToken */
        $jwtToken = Mockery::mock(JWT::class);
        $jwtToken->makePartial();
        $jwtToken->shouldReceive('decode')->andReturn([
            SsoClaimTypes::ISSUER => $authority,
            SsoClaimTypes::AUDIENCE => $audience,
        ]);
        $jwtToken->shouldReceive('getToken')->andReturn($token);

        $this->app['config']->set('sso-client.audience', null);
        $this->app['config']->set('sso-client.authority', $authority);

        // Act 
        $result = $jwtToken->isValid();

        // Assert
        $this->assertTrue($result);
    }

    /** @test */
    public function isValid_WithAnotherAudience_ShouldReturnedFalse(): void
    {
        // Arrange
        $audience = "https://sso.talan.group";
        $authority = "https://sso.talan.group";
        $token = $this->getToken();

        /** @var MockInterface|JWT jwtToken */
        $jwtToken = Mockery::mock(JWT::class);
        $jwtToken->makePartial();
        $jwtToken->shouldReceive('decode')->andReturn([
            SsoClaimTypes::ISSUER => $authority,
            SsoClaimTypes::AUDIENCE => $audience,
        ]);
        $jwtToken->shouldReceive('getToken')->andReturn($token);

        $this->app['config']->set('sso-client.audience', "https://another-sso.talan.group");
        $this->app['config']->set('sso-client.authority', $authority);

        // Act 
        $result = $jwtToken->isValid();

        // Assert
        $this->assertFalse($result);
    }

    /** @test */
    public function isValid_WithAnotherIssuer_ShouldReturnedFalse(): void
    {
        // Arrange
        $audience = "https://sso.talan.group";
        $authority = "https://sso.talan.group";
        $token = $this->getToken();

        /** @var MockInterface|JWT jwtToken */
        $jwtToken = Mockery::mock(JWT::class);
        $jwtToken->makePartial();
        $jwtToken->shouldReceive('decode')->andReturn([
            SsoClaimTypes::ISSUER => $authority,
            SsoClaimTypes::AUDIENCE => $audience,
        ]);
        $jwtToken->shouldReceive('getToken')->andReturn($token);

        $this->app['config']->set('sso-client.audience', $audience);
        $this->app['config']->set('sso-client.authority', "https://another-sso.talan.group");

        // Act 
        $result = $jwtToken->isValid();

        // Assert
        $this->assertFalse($result);
    }

    /** @test */
    public function isValid_WithAnotherIssuerAndAudience_ShouldReturnedFalse(): void
    {
        // Arrange
        $audience = "https://sso.talan.group";
        $authority = "https://sso.talan.group";
        $token = $this->getToken();

        /** @var MockInterface|JWT jwtToken */
        $jwtToken = Mockery::mock(JWT::class);
        $jwtToken->makePartial();
        $jwtToken->shouldReceive('decode')->andReturn([
            SsoClaimTypes::ISSUER => $authority,
            SsoClaimTypes::AUDIENCE => $audience,
        ]);
        $jwtToken->shouldReceive('getToken')->andReturn($token);

        $this->app['config']->set('sso-client.audience', "https://another-sso.talan.group");
        $this->app['config']->set('sso-client.authority', "https://another-sso.talan.group");

        // Act 
        $result = $jwtToken->isValid();

        // Assert
        $this->assertFalse($result);
    }

    ///////////////////////////////////////////////////////////////////////

    /** @test */
    public function getClaims_ShouldReturnedClaims(): void
    {
        // Arrange
        $audience = "https://sso.talan.group";
        $authority = "https://sso.talan.group";
        $token = $this->getToken();

        /** @var MockInterface|JWT jwtToken */
        $jwtToken = Mockery::mock(JWT::class);
        $jwtToken->makePartial();
        $jwtToken->shouldReceive('decode')->andReturn([
            SsoClaimTypes::ISSUER => $authority,
            SsoClaimTypes::AUDIENCE => $audience,
        ]);
        $jwtToken->shouldReceive('getToken')->andReturn($token);

        $this->app['config']->set('sso-client.authority', "https://another-sso.talan.group");

        // Act 
        $result = $jwtToken->getClaims();

        // Assert
        $this->assertEquals($authority, $result[SsoClaimTypes::ISSUER]);
        $this->assertEquals($audience, $result[SsoClaimTypes::AUDIENCE]);
    }
}
