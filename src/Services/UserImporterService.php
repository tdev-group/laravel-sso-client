<?php

namespace LaravelSsoClient\Services;

use Illuminate\Container\Container;
use LaravelSsoClient\JWT;
use LaravelSsoClient\Contracts\IUserImporterService;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Log;

class UserImporterService implements IUserImporterService
{
    /**
     * Gets import handlers.
     *
     * @var Array{IImportHandler}
     */
    private $handlers;

    public function __construct()
    {
        $this->handlers = [];

        $classes = Config::get('sso-client.import_handlers');
        foreach ($classes as $class) {
            $this->handlers[] = Container::getInstance()->make($class);
        }
    }

    /**
     * {@inheritDoc}
     */
    public function create(JWT $jwt)
    {
        try {
            $model = $this->createModel();

            return $this->update($jwt, $model);
        } catch (\Throwable $exception) {
            Log::error('Failed to create user model', [
                'innerException' => $exception
            ]);

            throw $exception;
        }
    }

    /**
     * {@inheritDoc}
     */
    public function update(JWT $jwt, Model $user)
    {
        try {
            $ssoService = new SsoService($jwt);

            $claims = $jwt->getClaims();
            $userInfo = $ssoService->getUserInfo();

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
