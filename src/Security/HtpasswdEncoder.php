<?php

namespace Htpasswd\Security;

use Symfony\Component\Security\Core\Encoder\PasswordEncoderInterface;
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
 * @link https://github.com/whitehat101/apr1-md5  the used implementation of the `apr1-md` algorithm
 *       https://www.php.net/manual/de/function.password-verify.php the `password_*` methods are used for the `crypt`/`bcrypt` hashes
 *
 * @package Htpasswd
 */
class HtpasswdEncoder implements PasswordEncoderInterface
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
     * @return bool|string
     */
    public static function encodeBCRYPT(string $raw, ?string $salt = null, int $costs = 10)
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
    public static function encodeSHA1(string $raw)
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
    public function encodePassword($raw, $salt)
    {
        return self::encodeMD5($raw, $salt);
    }

    /**
     * Returns `true` if the submitted `$raw` passwords matches the existing `$encoded` password, else `false`.
     *
     * {@inheritDoc}
     */
    public function isPasswordValid($encoded, $raw, $salt)
    {
        // select password check depending on the algorithm used to generate the $encoded phrase
        switch( $this->getHashMethod($encoded) )
        {
            case self::HASH_BCRYPT:
                return password_verify($raw, $encoded);
            case self::HASH_MD5:
                return APR1_MD5::check($raw, $encoded);
                break;
            case self::HASH_SHA1:
                return hash_equals($encoded, $this->encodeSHA1($raw));
            case self::HASH_CRYPT_OR_PLAIN:
                return password_verify($raw, $encoded) || ( strcmp($encoded, $raw) === 0 );
            case self::HASH_PLAIN:
                return ( strcmp($encoded, $raw) === 0 );
        }

        return false;
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

    public function needsRehash(string $encoded): bool
    {
        return false;
    }
}