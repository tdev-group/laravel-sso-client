<?php

namespace LaravelSsoClient\Tests\Unit;

use GuzzleHttp\Client;
use Illuminate\Support\Facades\Cache;
use LaravelSsoClient\Exceptions\RequestTokenFailedException;
use LaravelSsoClient\JWT;
use LaravelSsoClient\Requests\CreateUserRequest;
use LaravelSsoClient\Services\SsoService;
use Mockery;
use Mockery\MockInterface;

/**
 * @group unit
 * @group sso-service
 */
class SsoServiceTest extends TestCase
{
    private static $token = [
        "access_token" => "eyJhbGciOiJSUzI1NiIsImtpZCI6IjNDN0VGRkRGOURGM0Y1QzNCRjM1OThBMkNFOTlDOTRFM0ZBMTE5MTJSUzI1NiIsInR5cCI6ImF0K2p3dCIsIng1dCI6IlBIN18zNTN6OWNPX05aaWl6cG5KVGotaEdSSSJ9.eyJuYmYiOjE2NTQwNjc3NzcsImV4cCI6MTY1NDA3MTM3NywiaXNzIjoiaHR0cHM6Ly9pZHNkLnRhbGFuLmdyb3VwIiwiYXVkIjpbImh0dHBzOi8vbG9jYWxob3N0OjgwODkiLCJodHRwczovL2xvY2FsaG9zdDo0NDMyNCIsImh0dHBzOi8vY2xvdWQtZGV2LnRhbGFuLmdyb3VwIiwiaHR0cHM6Ly9pZHNkLnRhbGFuLmdyb3VwL3Jlc291cmNlcyJdLCJjbGllbnRfaWQiOiJsb2NhbC10cHJvLWNsaWVudC1jcmVkZW50aWFscyIsImp0aSI6IjQ3N0NCRDBGNzY5NjQzMjhFNUM0OUFCNTU0Q0NEQTFDIiwiaWF0IjoxNjU0MDY3Nzc3LCJzY29wZSI6WyJjbG91ZC1hcGkiXX0.Z91GqsXvwYKzyO_uBOqEnUFbCGaLsGMKtmNqyo-QUsz2Qjs5l1cb5FJCb2V4UnV5CBUV4z4eC-bRgZ_KYxEoAs0rW_Xx0qUEPXw5EZQR-Vt6ZhSCJZ7zV2SQWQFBDtSdfL6H0QB94i4c451_W6ToxVZ4QDdGz6s5J3dzmhpnBzwyPBgXmLhGrk6SzWfDfE66mDnfUz4Jr4Z2vlgJeG4fXQpPN2VtSHQ8jqva_yAzwOrqKce-nAnBUNActcE9h4MrwlpqLngPvYhPfNWQiV9sdCDV8wqdk0ycZr2gIkYjzWtcE7CeZZwvfUdZOxVxmbPbfP5FHpu7kDi0AywuST46Jg",
        "expires_in" => 3600,
        "token_type" => "Bearer",
        "scope" => "cloud-api"
    ];

    /** @test */
    public function getClientCredentialsToken_ShouldReturnedToken(): void
    {
        // Arrange
        $token = static::$token;

        /** @var MockInterface|Client httpClient */
        $httpClient = Mockery::mock(Client::class);
        $httpClient->shouldReceive('post->getStatusCode')->andReturn(200);
        $httpClient->shouldReceive('post->getBody')->andReturn(json_encode($token));

        /** @var MockInterface|SsoService service */
        $service = Mockery::mock(SsoService::class);
        $service->makePartial();
        $service->shouldReceive('makeHttpClient')->andReturn($httpClient);

        // Act 
        $result = $service->getClientCredentialsToken();

        // Assert
        $this->assertEquals($token['access_token'], $result);
        $this->assertEquals($token['access_token'], Cache::get('jwt-guard::client-credentials-token'));
    }

    /** @test */
    public function getClientCredentialsToken_WithSsoServerError_ShouldReturnedBearerToken(): void
    {
        // Arrange
        $token = static::$token;

        /** @var MockInterface|Client httpClient */
        $httpClient = Mockery::mock(Client::class);
        $httpClient->shouldReceive('post->getStatusCode')->andReturn(400);
        $httpClient->shouldReceive('post->getBody->getContents')->andReturn("Bad request");

        /** @var MockInterface|SsoService service */
        $service = Mockery::mock(SsoService::class);
        $service->makePartial();
        $service->shouldReceive('makeHttpClient')->andReturn($httpClient);

        // Assert
        $this->expectException(RequestTokenFailedException::class);
        $this->expectExceptionMessage('Request a client credentials token failed, the server returned (status code: 400)');

        // Act 
        $service->getClientCredentialsBearerToken();

        // Assert
        $this->assertNull(Cache::get('jwt-guard::client-credentials-token'));
    }

    /** @test */
    public function getClientCredentialsToken_WithCachedToken_ShouldReturnedcachedToken(): void
    {
        // Arrange
        $token = static::$token;

        /** @var MockInterface|Client httpClient */
        $httpClient = Mockery::mock(Client::class);
        $httpClient->shouldReceive('post->getStatusCode')->andReturn(200);
        $httpClient->shouldReceive('post->getBody')->andReturn(json_encode($token));

        /** @var MockInterface|SsoService service */
        $service = Mockery::mock(SsoService::class);
        $service->makePartial();
        $service->shouldReceive('makeHttpClient')->andReturn($httpClient);

        Cache::add('jwt-guard::client-credentials-token', 'test-cached-token');

        // Act 
        $result = $service->getClientCredentialsToken();

        // Assert
        $this->assertEquals('test-cached-token', $result);
    }

    ///////////////////////////////////////////////////////////////////////

    /** @test */
    public function getClientCredentialsBearerToken_ShouldReturnedBearerToken(): void
    {
        // Arrange
        $token = static::$token;

        /** @var MockInterface|Client httpClient */
        $httpClient = Mockery::mock(Client::class);
        $httpClient->shouldReceive('post->getStatusCode')->andReturn(200);
        $httpClient->shouldReceive('post->getBody')->andReturn(json_encode($token));

        /** @var MockInterface|SsoService service */
        $service = Mockery::mock(SsoService::class);
        $service->makePartial();
        $service->shouldReceive('makeHttpClient')->andReturn($httpClient);

        // Act 
        $result = $service->getClientCredentialsBearerToken();

        // Assert
        $this->assertEquals('Bearer ' . $token['access_token'], $result);
        $this->assertEquals($token['access_token'], Cache::get('jwt-guard::client-credentials-token'));
    }

    /** @test */
    public function getClientCredentialsBearerToken_WithCachedToken_ShouldReturnedBearerToken(): void
    {
        // Arrange
        $token = static::$token;

        /** @var MockInterface|Client httpClient */
        $httpClient = Mockery::mock(Client::class);
        $httpClient->shouldReceive('post->getStatusCode')->andReturn(200);
        $httpClient->shouldReceive('post->getBody')->andReturn(json_encode($token));

        /** @var MockInterface|SsoService service */
        $service = Mockery::mock(SsoService::class);
        $service->makePartial();
        $service->shouldReceive('makeHttpClient')->andReturn($httpClient);

        Cache::add('jwt-guard::client-credentials-token', 'test-cached-token');

        // Act 
        $result = $service->getClientCredentialsBearerToken();

        // Assert
        $this->assertEquals('Bearer test-cached-token', $result);
    }

    ///////////////////////////////////////////////////////////////////////

    /** @test */
    public function getDiscoveryDocument_ShouldReturnedDocument(): void
    {
        // Arrange
        $document = ['document_data' => true];

        /** @var MockInterface|Client httpClient */
        $httpClient = Mockery::mock(Client::class);
        $httpClient->shouldReceive('get->getBody')->andReturn(json_encode($document));

        /** @var MockInterface|SsoService service */
        $service = Mockery::mock(SsoService::class);
        $service->makePartial();
        $service->shouldReceive('makeHttpClient')->andReturn($httpClient);

        // Act 
        $result = $service->getDiscoveryDocument();

        // Assert
        $this->assertEquals($document, $result);
        $this->assertEquals($document, Cache::get('jwt-guard::discovery'));
    }

    ///////////////////////////////////////////////////////////////////////

    /** @test */
    public function getPublicKeys_ShouldReturnedKeys(): void
    {
        // Arrange
        $keys = ['key' => true];

        /** @var MockInterface|Client httpClient */
        $httpClient = Mockery::mock(Client::class);
        $httpClient->shouldReceive('get->getBody')->andReturn(json_encode($keys));

        /** @var MockInterface|SsoService service */
        $service = Mockery::mock(SsoService::class);
        $service->makePartial();
        $service->shouldReceive('makeHttpClient')->andReturn($httpClient);

        // Act 
        $result = $service->getPublicKeys();

        // Assert
        $this->assertEquals($keys, $result);
        $this->assertEquals($keys, Cache::get('jwt-guard::public-keys'));
    }

    ///////////////////////////////////////////////////////////////////////

    /** @test */
    public function getUserInfo_ShouldReturnedDocument(): void
    {
        // Arrange
        $userinfo = ['userinfo' => true];
        $bearer = $this->getBearerToken();
        $jwtToken = new JWT($this->makeRequest($bearer), $this->app->make(SsoService::class));

        /** @var MockInterface|Client httpClient */
        $httpClient = Mockery::mock(Client::class);
        $httpClient->shouldReceive('get->getBody')->andReturn(json_encode($userinfo));

        /** @var MockInterface|SsoService service */
        $service = Mockery::mock(SsoService::class);
        $service->makePartial();
        $service->shouldReceive('makeHttpClient')->andReturn($httpClient);

        // Act 
        $result = $service->getUserInfo($jwtToken);

        // Assert
        $this->assertEquals($userinfo, $result);
    }

    ///////////////////////////////////////////////////////////////////////

    /** @test */
    public function exportUser_ShouldReturnedDocument(): void
    {
        // Arrange
        $userId = ['id' => true];
        $bearer = $this->getBearerToken();
        $jwtToken = new JWT($this->makeRequest($bearer), $this->app->make(SsoService::class));

        /** @var MockInterface|Client httpClient */
        $httpClient = Mockery::mock(Client::class);
        $httpClient->shouldReceive('post->getBody')->andReturn(json_encode($userId));

        /** @var MockInterface|SsoService service */
        $service = Mockery::mock(SsoService::class);
        $service->makePartial();
        $service->shouldReceive('makeHttpClient')->andReturn($httpClient);
        $service->shouldReceive('getClientCredentialsBearerToken')->andReturn('Bearer ' . static::$token['access_token']);

        // Act 
        $result = $service->exportUser(new CreateUserRequest(
            "email",
            "name",
            "givenName",
            "familyName"
        ));

        // Assert
        $this->assertEquals($userId, $result);
    }
}
