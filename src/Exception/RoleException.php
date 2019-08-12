<?php

namespace Htpasswd\Exception;

use function sprintf;

/**
 * Class RoleException
 *
 * @package Htpasswd
 */
class RoleException extends \UnexpectedValueException
{
    /**
     * the path of the htpasswd file
     *
     * @var string
     */
    protected $htpasswdPath = '';

    /**
     * the line of the current exception inside the htpasswd file
     *
     * @var int
     */
    protected $htpasswdLine = 0;

    /**
     * the parsed role
     *
     * @var string
     */
    protected $htpasswdRole = '';

    /**
     * Overrides {@see \Exception::__construct()} to pass the path, line no and the parsed role of the htpasswd file.
     *
     * @param string $message the error message
     * @param string $path    the path of the htpasswd file
     * @param int    $line    the line of the current exception inside the htpasswd file
     * @param string $role    the parsed role
     */
    public function __construct(string $message, string $path, int $line, string $role)
    {
        $this->htpasswdPath = $path;
        $this->htpasswdLine = $line;
        $this->htpasswdRole = $role;
        parent::__construct($message);
    }

    /**
     * Each role is not allowed to contain whitespaces ore line breaks. The role must be one word (regex _\w_).
     *
     * @param string $path          the path of the htpasswd file
     * @param int    $line          the line of the current exception inside the htpasswd file
     * @param string $incorrectRole the parsed role
     *
     * @return self
     */
    public static function createOneWordOnlyException(string $path, int $line, string $incorrectRole)
    {
        $message = sprintf('Htpasswd: Each role must be exactly one word, found "%s" in %s:%d', $incorrectRole, $path, $line);

        return new self($message, $path, $line, $incorrectRole);
    }

    /**
     * Each role is must start with "ROLE_".
     *
     * @param string $path          the path of the htpasswd file
     * @param int    $line          the line of the current exception inside the htpasswd file
     * @param string $incorrectRole the parsed role
     *
     * @return self
     */
    public static function createStartWithRoleException(string $path, int $line, string $incorrectRole)
    {
        $message = sprintf('Htpasswd: Each role must start with "ROLE_", found "%s" in %s:%d', $incorrectRole, $path, $line);

        return new self($message, $path, $line, $incorrectRole);
    }

    /**
     * Returns the the path of the htpasswd file.
     *
     * @return string
     */
    public function getHtpasswdPath(): string
    {
        return $this->htpasswdPath;
    }

    /**
     * Returns the line of the current exception inside the htpasswd file.
     *
     * @return int
     */
    public function getHtpasswdLine(): int
    {
        return $this->htpasswdLine;
    }

    /**
     * Returns the the parsed role.
     *
     * @return string
     */
    public function getHtpasswdRole(): string
    {
        return $this->htpasswdRole;
    }
}
