<?php

namespace LaravelSsoClient\Requests;

class CreateUserRequest
{
    /**
     * Gets or sets user's email address.
     *
     * @var string
     */
    public $email;

    /**
     * Gets or sets user's login.
     *
     * @var string
     */
    public $username;

    /**
     * Gets or sets user's name.
     *
     * @var string
     */
    public $name;

    /**
     * Gets or sets user's given name.
     *
     * @var string
     */
    public $givenName;

    /**
     * Gets or sets user's family name.
     *
     * @var string
     */
    public $familyName;

    /**
     * Gets or sets user's phone number.
     *
     * @var string
     */
    public $phoneNumber;

    /**
     * Creates a new CreateUserRequest.
     *
     * @param string $email User's email address.
     * @param string $name User's name.
     * @param string $givenName  User's given name.
     * @param string $familyName User's family name.
     * @param string|null $username User's login.
     * @param string|null $phoneNumber User's phone number.
     */
    public function __construct(
        $email,
        $name,
        $givenName,
        $familyName,
        $username = null,
        $phoneNumber = null
    ) {
        $this->name = $name;
        $this->email = $email;
        $this->username = $username;
        $this->givenName = $givenName;
        $this->familyName = $familyName;
        $this->phoneNumber = $phoneNumber;
    }

    /**
     * Converts this object to array.
     *
     * @return array
     */
    public function toArray()
    {
        return [
            'email' => $this->email,
            'username' => $this->username,
            'name' => $this->name,
            'given_name' => $this->givenName,
            'family_name' => $this->familyName,
            'phone_number' => $this->phoneNumber,
        ];
    }
}
