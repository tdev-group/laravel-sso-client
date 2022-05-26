<?php

namespace LaravelSsoClient;

use LaravelSsoClient\Services\SsoService;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWK;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use Illuminate\Validation\UnauthorizedException;
use UnexpectedValueException;

class JWT
{
    /**
     * Gets a JWT token.
     *
     * @var string|null
     */
    protected $token;

    /**
     * Gets claims of the JWT token.
     *
     * @var array|null
     */
    protected $claims;

    /**
     * Gets the request instance.
     *
     * @var Request
     */
    protected $request;

    /**
     * Gets allowed algorithms.
     */
    private const ALLOWED_ALGORITHMS = ['RS256'];

    /**
     * Create a new jwt.
     *
     * @param Request  $request
     */
    public function __construct(Request $request)
    {
        $this->token = null;
        $this->claims = null;
        $this->request = $request;
    }

    /**
     * Determine if a token is valid.
     * 
     * @return bool
     */
    public function isValid()
    {
        try {
            $this->getClaims();

            return true;
        } catch (\Throwable $exception) {
            return false;
        }
    }

    /**
     * Returns the JWT token claims.
     * 
     * @return array
     * @throws UnauthorizedException If a JWT token is empty or invalid.
     */
    public function getClaims(string $name  = null, $default = null)
    {
        try {
            if (is_null($this->claims)) {
                $token = $this->getToken($this->request);

                $this->claims = $this->validIssuer(
                    $this->decode($token)
                );
            }

            return Arr::get($this->claims, $name, $default);
        } catch (ExpiredException $exception) {
            throw $exception;
        } catch (UnauthorizedException $exception) {
            throw $exception;
        } catch (\Throwable $exception) {
            throw new UnauthorizedException("Invalid JWT token.", 0, $exception);
        }
    }

    /**
     * Returns the subject of the JWT token.
     * 
     * @return string
     * @throws UnauthorizedException If not authorized.
     */
    public function getSubject()
    {
        return $this->getClaims('sub');
    }

    /**
     * Decodes the JWT token.
     *
     * @param string $token 
     * @return array The list of identity claims.
     */
    public function decode(string $token)
    {
        try {
            $publicKeys = SsoService::getPublicKeys();

            $claims = (array) \Firebase\JWT\JWT::decode(
                $token,
                JWK::parseKeySet($publicKeys),
                static::ALLOWED_ALGORITHMS
            );

            return $claims;
        } catch (\Throwable $exception) {
            Log::info('Failed to token decode', [
                'token' => $token,
                'exception' => $exception
            ]);

            throw $exception;
        }
    }

    /**
     * Returns the JWT token from request. Retrieves only Bearer tokens.
     * 
     * @param Request $request An instance of the Request.
     * @return string
     * @throws UnauthorizedException If the authorization header is empty.
     * @throws UnauthorizedException If a token is not a bearer token.
     */
    public function getToken()
    {
        if (is_null($this->token)) {
            $authorization = $this->getAuthorizationHeader();

            if (!Str::startsWith($authorization, 'Bearer ')) {
                throw new UnauthorizedException('Invalid authorization token. (Not Bearer token)');
            }

            $token = trim(Str::substr($authorization, strlen('Bearer ')));

            if (empty($token)) {
                throw new UnauthorizedException('Invalid authorization token.');
            }

            $this->token = $token;
        }

        return $this->token;
    }

    /**
     * Validates a token audience.
     *
     * @return bool
     */
    public function validAudience()
    {
        $audience = Config::get('sso-client.audience');

        if (!$audience) {
            return true;
        }

        $validateAudience = Config::get('sso-client.validate_audience', false);

        if (!$validateAudience) {
            return true;
        }

        $aud = Arr::wrap($this->getClaims('aud', ""));

        return in_array($audience, $aud);
    }

    /**
     * Returns the Authorization header from request.
     *
     * @param Request $request An instance of the Request.
     * @return string
     */
    public function getAuthorizationHeader()
    {
        $authorization = $this->request->headers->get('Authorization');

        if (empty($authorization)) {
            throw new UnauthorizedException('Authorization header is empty.');
        }

        return $authorization;
    }

    /**
     * Checks the issuer of the token.
     * If the issuer is valid returns the provided claims, otherwise throws an exception.
     *
     * @param array $claims
     * @return array Provided claims.
     * @throws UnexpectedValueException If the claim issuer does not allowed.
     */
    private function validIssuer(array $claims)
    {
        $issuer = $claims['iss'];
        $authority = Config::get('sso-client.authority');

        if ($claims['iss'] !== $issuer) {
            throw new UnexpectedValueException("Invalid issuer ({$issuer}), should be ({$authority}).");
        }

        return $claims;
    }
}
