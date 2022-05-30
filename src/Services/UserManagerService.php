<?php

namespace LaravelSsoClient\Services;

use Illuminate\Container\Container;
use LaravelSsoClient\JWT;
use LaravelSsoClient\Contracts\IUserManagerService;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;

class UserManagerService implements IUserManagerService
{
    /**
     * Gets import handlers.
     *
     * @var Array{IImportHandler}
     */
    private $handlers;

    /**
     * Gets an instance of the SsoService.
     *
     * @var SsoService
     */
    private $ssoService;

    public function __construct(SsoService $ssoService)
    {
        $this->handlers = [];
        $this->ssoService = $ssoService;

        $classes = Config::get('sso-client.import_handlers', []);
        foreach ($classes as $class) {
            $this->handlers[] = Container::getInstance()->make($class);
        }
    }

    /**
     * {@inheritDoc}
     */
    public function import(JWT $jwt)
    {
        return $this->update($jwt, $this->createModel());
    }

    /**
     * {@inheritDoc}
     */
    public function update(JWT $jwt, Model $user)
    {
        try {
            $claims = $jwt->getClaims();
            $userInfo = $this->ssoService->getUserInfo($jwt);

            foreach ($this->handlers as $handler) {
                $handler->handle($user, $claims, $userInfo);
            }

            $user->save();

            return $user;
        } catch (\Throwable $exception) {
            Log::error('Failed to update user\'s model', [
                'innerException' => $exception
            ]);

            throw $exception;
        }
    }

    /**
     * Create a new instance of the model.
     *
     * @return Model
     */
    protected function createModel()
    {
        $model = $this->normalizeClassName(Config::get('sso-client.model'));

        return new $model;
    }

    /**
     * Returns the normalized model class name.
     *
     * @param string $className A name of the model class.
     * @return string
     */
    protected function normalizeClassName(string $className)
    {
        return '\\' . ltrim($className, '\\');
    }
}
