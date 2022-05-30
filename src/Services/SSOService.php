<?php

namespace LaravelSsoClient\Services;

use LaravelSsoClient\JWT;
use GuzzleHttp\Client;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;

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
     * Returns a user info by jwt token.
     *
     * @param JWT $jwt Any JWT token.
     * @return array
     */
    public function getUserInfo(JWT $jwt)
    {
        try {
            $issuer = static::getAuthority();

            $url = $issuer . Config::get('sso-client.urls.userinfo');
            $bearer = $jwt->getAuthorizationHeader();

            $response = (new Client())->get($url, [
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
     * @param string $issuer The URL of a token issuer (iss).
     * @return array
     */
    public static function getPublicKeys(string $issuer = null)
    {
        if (is_null($issuer)) {
            $issuer = static::getAuthority();
        }

        $url = $issuer . Config::get('sso-client.urls.public_keys');
        $cacheLifetime = Config::get('sso-client.cache.lifetime');

        return Cache::remember(static::PUBLIC_KEYS_CACHE_NAME, $cacheLifetime, function () use ($url) {
            try {
                $response = (new Client())->get($url, ['verify' => Config::get('sso-client.authority_verify_ssl', true)]);

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
     * @param string $issuer The URL of a token issuer (iss).
     * @return array
     */
    public static function getDiscoveryDocument(string $issuer = null)
    {
        if (is_null($issuer)) {
            $issuer = static::getAuthority();
        }

        $url = $issuer . Config::get('sso-client.urls.discovery_document');
        $cacheLifetime = Config::get('sso-client.cache.long_lifetime');

        return Cache::remember(static::DISCOVERY_DOCUMENT_CACHE_NAME, $cacheLifetime, function () use ($url) {
            try {
                $response = (new Client())->get($url, ['verify' => Config::get('sso-client.authority_verify_ssl', true)]);

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
     * Returns the authority server.
     *
     * @return string
     */
    private static function getAuthority()
    {
        return Config::get('sso-client.authority');
    }
}
