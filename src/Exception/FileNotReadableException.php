<?php

namespace Htpasswd\Exception;

use Exception;
use Symfony\Component\Filesystem\Exception\IOException;
use function sprintf;

/**
 * Class FileNotReadableException
 *
 * @package Htpasswd
 */
class FileNotReadableException extends IOException
{
    /**
     * FileNotReadableException constructor.
     *
     * @param string|null    $message
     * @param int            $code
     * @param Exception|null $previous
     * @param string|null    $path the file which is not readable
     */
    public function __construct(string $message = null, int $code = 0, Exception $previous = null, string $path = null)
    {
        if( null === $message )
        {
            if( null === $path )
            {
                $message = 'File could not be read. Please check file permissions.';
            }
            else
            {
                $message = sprintf('File could not be read. Please check file permissions of file "%s".', $path);
            }
        }

        parent::__construct($message, $code, $previous, $path);
    }
}
