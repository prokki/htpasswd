<?php

namespace Htpasswd\Security;

use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\User;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use function explode;
use function file;
use function get_class;
use function strtolower;
use function substr;
use function trim;

/**
 * The {@see \Htpasswd\Security\HtpasswdProvider} reads user from the
 * htpasswd file. The default location of the file is `%kernel.project_dir%/.htpasswd` but you can change
 * the directory or file path via the configuration parameter `Htpasswd.path`.
 *
 * Take a look at {@link http://httpd.apache.org/docs/current/misc/password_encryptions.html} to get more details
 * about the htpasswd file.
 */
class HtpasswdProvider implements UserProviderInterface
{
    /**
     * the path of the htpasswd file
     *
     * @var string
     */
    protected $path = '';

    /**
     * the default roles which will be assigned to each user
     *
     * @var string[]
     */
    protected $roles = array();


    /**
     * @var User[]
     */
    protected $users = array();

    /**
     * HtpasswdProvider constructor.
     *
     * @param string   $path  the path of the htpasswd file
     *                        the path was checked in the extension, it exists and is readable
     * @param string[] $roles the default roles which will be assigned to each user
     */
    public function __construct(string $path, array $roles)
    {
        $this->path  = $path;
        $this->roles = $roles;

        $this->readUsersFromFile();
    }

    /**
     * Reads all users from the five htpasswd file and loads them into the provider.
     *
     * Prerequisites: Properties `path` and `roles` must be set.
     */
    protected function readUsersFromFile()
    {
        // read line by line
        foreach( file($this->path, FILE_SKIP_EMPTY_LINES) as $_line )
        {

            $_line = trim($_line);

            // ignore empty lines
            if( empty($_line) )
            {
                continue 1;
            }

            // ignore lines starting with #
            // https://httpd.apache.org/docs/2.4/configuring.html
            if( substr($_line, 0, 1) === '#' )
            {
                continue 1;
            }

            // get user and (encrypted) password
            list($_user, $_encryptedPassword, $_roles) = explode(':', $_line);

            $_roles = $this->normalizeRoles($_roles);

            // and add to provider
            $this->createUser($_user, $_encryptedPassword);
        }
    }

    protected function normalizeRoles(string $roles)
    {

    }

    /**
     * Adds a new to the provider.
     *
     * @param string $userName          the user name
     * @param string $encryptedPassword the encrypted password hash
     */
    public function createUser(string $userName, string $encryptedPassword)
    {
        $this->users[ strtolower($userName) ] = new User($userName, $encryptedPassword, $this->roles);
    }

    /**
     * {@inheritdoc}
     */
    public function loadUserByUsername($username)
    {
        $user = $this->getUser($username);

        return new User($user->getUsername(), $user->getPassword(), $user->getRoles(), $user->isEnabled(), $user->isAccountNonExpired(), $user->isCredentialsNonExpired(), $user->isAccountNonLocked());
    }

    /**
     * {@inheritdoc}
     */
    public function refreshUser(UserInterface $user)
    {
        if( !$user instanceof User )
        {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', get_class($user)));
        }

        $storedUser = $this->getUser($user->getUsername());

        return new User($storedUser->getUsername(), $storedUser->getPassword(), $storedUser->getRoles(), $storedUser->isEnabled(), $storedUser->isAccountNonExpired(), $storedUser->isCredentialsNonExpired() && $storedUser->getPassword() === $user->getPassword(), $storedUser->isAccountNonLocked());
    }

    /**
     * {@inheritdoc}
     */
    public function supportsClass($class)
    {
        return ( User::class === $class );
    }

    /**
     * Returns the user by given username.
     *
     * @param string $username The username
     *
     * @return User
     *
     * @throws UsernameNotFoundException if user whose given username does not exist
     */
    private function getUser($username)
    {
        if( !isset($this->users[ strtolower($username) ]) )
        {
            $ex = new UsernameNotFoundException(sprintf('User "%s" does not exist.', $username));
            $ex->setUsername($username);

            throw $ex;
        }

        return $this->users[ strtolower($username) ];
    }
}