<?php

namespace LaravelSsoClient\Services;

use LaravelSsoClient\JWT;
use GuzzleHttp\Client;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
use LaravelSsoClient\Exceptions\RequestTokenFailedException;
use LaravelSsoClient\Exceptions\UserExportFailedException;
use LaravelSsoClient\Requests\CreateUserRequest;

class SsoService
{
    /**
     * Gets the public keys cache name.
     */
    private const PUBLIC_KEYS_CACHE_NAME = 'jwt-guard::public-keys';

    /**
     * Gets the discovery document cache name.
     */
    private const DISCOVERY_DOCUMENT_CACHE_NAME = 'jwt-guard::discovery';

    /**
     * Gets the client credentials token cache name.
     */
    private const CLIENT_CREDENTIAL_TOKEN_CACHE_NAME = 'jwt-guard::client-credentials-token';

    /**
     * Exports (Creates) a user to the single sign-on server.
     *
     * @param CreateUserRequest $request
     * @return string Exported user identifier.
     */
    public function exportUser(CreateUserRequest $request)
    {
        try {
            $uri = Config::get('sso-client.urls.createuser');
            $authority = static::getAuthority();

            $response = static::makeHttpClient($authority)->post($uri, [
                'verify' => Config::get('sso-client.authority_verify_ssl', true),
                'headers' => [
                    'Accept' => 'application/json',
                    'Content-Type' => 'application/json',
                    'Authorization' => $this->getClientCredentialsBearerToken()
                ],
                'json' => $request->toArray()
            ]);

            return json_decode($response->getBody(), true);
        } catch (\Throwable $exception) {
            Log::error('Failed to export a user to the sso server', [
                'innerException' => $exception
            ]);

            throw $exception;
        }
    }

    /**
     * Returns a user info by jwt token.
     *
     * @param JWT $jwt Any JWT token.
     * @return array
     */
    public function getUserInfo(JWT $jwt)
    {
        try {
            $authority = static::getAuthority();

            $url = Config::get('sso-client.urls.userinfo');
            $bearer = $jwt->getAuthorizationHeader();

            $response = static::makeHttpClient($authority)->get($url, [
                'verify' => Config::get('sso-client.authority_verify_ssl', true),
                'headers' => [
                    'Accept' => 'application/json',
                    'Content-Type' => 'application/json',
                    'Authorization' => $bearer
                ]
            ]);

            return json_decode($response->getBody(), true);
        } catch (\Throwable $exception) {
            Log::error('Failed to get user\'s information from the authority service', [
                'innerException' => $exception
            ]);

            throw $exception;
        }
    }

    /**
     * Gets the public keys from issuer.
     *
     * @param string $authority The URL of a token authority (iss).
     * @return array
     */
    public static function getPublicKeys(string $authority = null)
    {
        $url = Config::get('sso-client.urls.public_keys');
        $authority = $authority ?? static::getAuthority();
        $cacheLifetime = Config::get('sso-client.cache.lifetime');

        return Cache::remember(self::PUBLIC_KEYS_CACHE_NAME, $cacheLifetime, function () use ($authority, $url) {
            try {
                $response = static::makeHttpClient($authority)->get($url, ['verify' => Config::get('sso-client.authority_verify_ssl', true)]);

                return json_decode($response->getBody(), true);
            } catch (\Throwable $exception) {
                Log::error('Failed to get public keys from the authority service', [
                    'innerException' => $exception
                ]);

                throw $exception;
            }
        });
    }

    /**
     * Gets the discovery document from issuer server.
     *
     * @param string $authority The URL of a token authority (iss).
     * @return array
     */
    public static function getDiscoveryDocument(string $authority = null)
    {
        $uri = Config::get('sso-client.urls.discovery_document');
        $cacheLifetime = Config::get('sso-client.cache.long_lifetime');

        return Cache::remember(self::DISCOVERY_DOCUMENT_CACHE_NAME, $cacheLifetime, function () use ($authority, $uri) {
            try {
                $response = static::makeHttpClient($authority)->get($uri, ['verify' => Config::get('sso-client.authority_verify_ssl', true)]);

                return json_decode($response->getBody(), true);
            } catch (\Throwable $exception) {
                Log::error('Failed to get discovery information from the authority service', [
                    'innerException' => $exception
                ]);

                throw $exception;
            }
        });
    }

    /**
     * Retrieves a client credentials token from single sign-on server.
     *
     * @param string $authority
     * @return string Retrieved access token.
     */
    public function getClientCredentialsToken($authority = null)
    {
        if ($token = Cache::get(self::CLIENT_CREDENTIAL_TOKEN_CACHE_NAME)) {
            return $token;
        }

        $uri = Config::get('sso-client.urls.token');
        $authority = $authority ?? static::getAuthority();

        $response = static::makeHttpClient($authority)->post($uri, [
            'verify' => Config::get('sso-client.authority_verify_ssl', true),
            'form_params' => [
                "client_id" => Config::get('sso-client.client_credentials.client_id', true),
                "client_secret" => Config::get('sso-client.client_credentials.client_secret', true),
                "grant_type" => "client_credentials",
                "scope" => Config::get('sso-client.client_credentials.scope', true),
            ]
        ]);

        $statusCode = $response->getStatusCode();

        if ($statusCode === 200) {
            $responseData = json_decode($response->getBody(), true);

            $expiresIn = $responseData['expires_in'];
            $accessToken = $responseData['access_token'];

            // Converts seconds to minutes and subtract 2 minutes.
            $cacheLifetime = ($expiresIn / 60) - 2;

            Cache::add(self::CLIENT_CREDENTIAL_TOKEN_CACHE_NAME, $accessToken, $cacheLifetime);

            return $accessToken;
        }

        Log::error("Request a client credentials token failed", [
            "authority" => $authority,
            "status_code" => $statusCode,
            "error_message" => $response->getBody()->getContents(),
        ]);

        throw new RequestTokenFailedException(
            "Request a client credentials token failed, the server returned (status code: {$statusCode})"
        );
    }

    public function getClientCredentialsBearerToken($authority = null)
    {
        return 'Bearer ' . $this->getClientCredentialsToken($authority);
    }

    /**
     * Creates a new HTTP client with base URL.
     * 
     * If baseURL was not provided, an authority URL will be used.
     *
     * @param string $baseURL
     * @return Client
     */
    public static function makeHttpClient($baseURL = null)
    {
        $baseURL = $baseURL ?? static::getAuthority();

        return new Client(['base_uri' => $baseURL]);
    }

    /**
     * Returns the authority server.
     *
     * @return string
     */
    protected static function getAuthority()
    {
        return Config::get('sso-client.authority');
    }
}
