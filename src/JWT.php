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
use stdClass;
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
     * Gets the JWT token user info.
     *
     * @var array|null
     */
    protected $userInfo;

    /**
     * Gets the request instance.
     *
     * @var Request
     */
    protected $request;

    /**
     * Gets the sso service instance.
     *
     * @var SsoService
     */
    protected $ssoService;

    /**
     * Gets allowed algorithms.
     */
    private const ALLOWED_ALGORITHMS = ['RS256'];

    /**
     * Create a new jwt.
     *
     * @param Request  $request
     */
    public function __construct(Request $request, SsoService $ssoService)
    {
        $this->token = null;
        $this->claims = null;
        $this->request = $request;
        $this->ssoService = $ssoService;
    }

    /**
     * Determine if a token is valid.
     *
     * @return bool
     */
    public function isValid()
    {
        try {
            return $this->validIssuer() && $this->validAudience();
        } catch (\Throwable $exception) {
            return false;
        }
    }

    /**
     * Returns the JWT token user info.
     *
     * @return array
     * @throws UnauthorizedException If a JWT token is empty or invalid.
     */
    public function getUserInfo(string $name  = null, $default = null)
    {
        try {
            if (is_null($this->userInfo)) {
                $this->userInfo = $this->ssoService->getUserInfo($this);
            }

            return Arr::get($this->userInfo, $name, $default);
        } catch (\Throwable $exception) {
            throw new UnauthorizedException("Invalid JWT token.", 0, $exception);
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
                $token = $this->getToken();

                $this->claims = $this->decode($token);
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
        return $this->getClaims(SsoClaimTypes::SUBJECT);
    }

    /**
     * Returns the scope of the JWT token.
     *
     * @return array
     * @throws
     */
    public function getScope()
    {
        return $this->getClaims(SsoClaimTypes::SCOPE);
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

            $headers = new stdClass();

            $claims = (array) \Firebase\JWT\JWT::decode(
                $token,
                JWK::parseKeySet($publicKeys),
                $headers
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
     * @return string
     * @throws UnexpectedValueException If the authorization header is empty.
     * @throws UnexpectedValueException If a token is not a bearer token.
     */
    public function getToken()
    {
        if (is_null($this->token)) {
            $authorization = $this->getAuthorizationHeader();

            if (!Str::startsWith($authorization, ['Bearer ', 'bearer '])) {
                throw new UnexpectedValueException('Invalid authorization token. (Not Bearer token)');
            }

            $token = trim(Str::substr($authorization, strlen('bearer ')));

            if (empty($token)) {
                throw new UnexpectedValueException('Invalid authorization token.');
            }

            $this->token = $token;
        }

        return $this->token;
    }

    /**
     * Returns the Authorization header from request.
     *
     * @param Request $request An instance of the Request.
     * @return string
     */
    public function getAuthorizationHeader()
    {
        $authorization = $this->request->header('Authorization');

        if (empty($authorization)) {
            throw new UnexpectedValueException('Authorization header is empty.');
        }

        return $authorization;
    }

    /**
     * Checks the issuer of the token.
     * If the issuer is valid returns the provided claims, otherwise throws an exception.
     *
     * @throws UnauthorizedException If the claim issuer does not allowed.
     */
    public function validIssuer()
    {
        try {
            $issuer = $this->getClaims(SsoClaimTypes::ISSUER, "");
            $authority = Config::get('sso-client.authority');

            return $issuer === $authority;
        } catch (\Throwable $exception) {
            return false;
        }
    }

    /**
     * Validates a token audience.
     *
     * @throws UnauthorizedException If the claim audience does not contain a required audience.
     */
    public function validAudience()
    {
        try {
            $audience = Config::get('sso-client.audience');

            if (!$audience) {
                return true;
            }

            $aud = Arr::wrap($this->getClaims(SsoClaimTypes::AUDIENCE, ""));

            return in_array($audience, $aud);
        } catch (\Throwable $exception) {
            return false;
        }
    }
}
