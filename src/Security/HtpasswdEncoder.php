<?php

namespace Htpasswd\Security;

use Symfony\Component\PasswordHasher\PasswordHasherInterface;
use WhiteHat101\Crypt\APR1_MD5;
use function base64_encode;
use function hash;
use function hash_equals;
use function password_hash;
use function password_verify;
use function sprintf;
use function strcmp;
use function strtoupper;
use function substr;

/**
 * The class {@see \Htpasswd\Security\HtpasswdEncoder} checks wether
 * the user has inserted the proper password.
 *
 * This class provides all encryption methods which are specified in the htpasswd specification,
 * see {@link http://httpd.apache.org/docs/current/misc/password_encryptions.html}.
 *
 * bcrypt
 *   "$2y$" + the result of the crypt_blowfish algorithm. See the APR source file crypt_blowfish.c for the details of the algorithm.
 * MD5
 *   "$apr1$" + the result of an Apache-specific algorithm using an iterated (1,000 times) MD5 digest of various combinations of a random 32-bit salt and the password. See the APR source file apr_md5.c for the details of the algorithm.
 * SHA1
 *   "{SHA}" + Base64-encoded SHA-1 digest of the password. Insecure.
 * CRYPT
 *   Unix only. Uses the traditional Unix crypt(3) function with a randomly-generated 32-bit salt (only 12 bits used) and the first 8 characters of the password. Insecure.
 * PLAIN TEXT (i.e. unencrypted)
 *   Windows & Netware only. Insecure.
 *
 * @link    https://github.com/whitehat101/apr1-md5  the used implementation of the `apr1-md` algorithm
 *       https://www.php.net/manual/de/function.password-verify.php the `password_*` methods are used for the `crypt`/`bcrypt` hashes
 *
 * @package Htpasswd
 */
class HtpasswdEncoder implements PasswordHasherInterface
{
    const HASH_PLAIN = '';
    const HASH_BCRYPT = '$2y$';
    const HASH_MD5 = '$apr1$';
    const HASH_SHA1 = '{SHA}';
    const HASH_CRYPT_OR_PLAIN = '';

    /**
     * Returns a password encrypted by `bcrypt`.
     *
     * @param string      $raw   the raw user input/password
     * @param string|null $salt  [optional] a phrase to salt the password
     * @param int         $costs [optional] the costs to encrypt the password between 1 and 31, default is 10
     *
     * @return string|false|null
     */
    public static function encodeBCRYPT(string $raw, ?string $salt = null, int $costs = 10): string|false|null
    {
        $options = ['costs' => $costs];

        if( !is_null($salt) )
        {
            $options[ 'salt' ] = $salt;
        }

        return password_hash($raw, PASSWORD_BCRYPT, $options);
    }

    /**
     * Returns a password encrypted by `apr-md5` algorithm.
     *
     * @param string      $raw  the raw user input/password
     * @param string|null $salt [optional] a phrase to salt the password, if no salt is passed a salt will be auto-generated
     *
     * @return string
     */
    public static function encodeMD5(string $raw, ?string $salt = null): string
    {
        return APR1_MD5::hash($raw, $salt);
    }

    /**
     * Returns a password encrypted by `sha1` algorithm.
     *
     * The sha1 hash is no recommended because the salt is not used. Each encryption returns the same hash value.
     *
     * @param string $raw the raw user input/password
     *
     * @return string
     */
    public static function encodeSHA1(string $raw): string
    {
        return sprintf('%s%s', self::HASH_SHA1, base64_encode(hash('sha1', $raw, true)));
    }

    /**
     * Returns a password encrypted by `apr-md5` algorithm.
     *
     * The default encryption of htpasswd is `apr1-md5`.
     * > man htpasswd
     * > OPTIONS
     * > -m    Use MD5 encryption for passwords. This is the default (since version 2.2.18).
     *
     * {@inheritDoc}
     */
    public function hash(string $plainPassword): string
    {
        return self::encodeMD5($plainPassword);
    }

    /**
     * Returns `true` if the submitted `$raw` passwords matches the existing `$encoded` password, else `false`.
     *
     * {@inheritDoc}
     */
    public function verify(string $hashedPassword, string $plainPassword): bool
    {
        // select password check depending on the algorithm used to generate the $encoded phrase
        return match ( $this->getHashMethod($hashedPassword) )
        {
            self::HASH_BCRYPT         => password_verify($plainPassword, $hashedPassword),
            self::HASH_MD5            => APR1_MD5::check($plainPassword, $hashedPassword),
            self::HASH_SHA1           => hash_equals($hashedPassword, $this->encodeSHA1($plainPassword)),
            self::HASH_CRYPT_OR_PLAIN => password_verify($plainPassword, $hashedPassword) || ( strcmp($hashedPassword, $plainPassword) === 0 ),
            self::HASH_PLAIN          => ( strcmp($hashedPassword, $plainPassword) === 0 ),
            default                   => false,
        };

    }

    /**
     * Returns the hash method which is used in the encrypted password hash.
     *
     * @param string $encoded
     *
     * @return string
     */
    protected function getHashMethod(string $encoded): string
    {

        if( self::HASH_BCRYPT === substr($encoded, 0, 4) )
        {
            // string starts with "$2y$"
            return self::HASH_BCRYPT;
        }
        elseif( self::HASH_MD5 === substr($encoded, 0, 6) )
        {
            // string starts with "$apr1$"
            return self::HASH_MD5;
        }
        elseif( self::HASH_SHA1 === substr($encoded, 0, 5) )
        {
            // string starts with "{SHA}"
            return self::HASH_SHA1;
        }

        // other encryption: only *nix like systems supports the `crypt` algorithm but
        // there is no prefix the check wether the password is encrypted or plain
        return ( strtoupper(substr(PHP_OS, 0, 3)) === 'WIN' ) ?
            // win = must be plain
            self::HASH_PLAIN :
            // *nux = plain or crypt
            self::HASH_CRYPT_OR_PLAIN;
    }

    /**
     * {@inheritDoc}
     */
    public function needsRehash(string $hashedPassword): bool
    {
        return false;
    }
}
