# Htpasswd

[![Latest Stable Version](https://poser.pugx.org/prokki/htpasswd/version)](https://packagist.org/packages/prokki/htpasswd)
[![Total Downloads](https://poser.pugx.org/prokki/htpasswd/downloads)](https://packagist.org/packages/prokki/htpasswd)
[![License](https://poser.pugx.org/prokki/htpasswd/license)](https://packagist.org/packages/prokki/htpasswd)
[![PHP v7.2](https://img.shields.io/badge/PHP-%E2%89%A57%2E2-0044aa.svg)](https://www.php.net/manual/en/migration72.new-features.php)
[![Symfony 4](https://img.shields.io/badge/Symfony-%E2%89%A54-0044aa.svg)](https://symfony.com/)

This symfony user provider reads user from the [htpasswd file](http://httpd.apache.org/docs/current/misc/password_encryptions.html).

To use the a htpasswd file you need to execute following three steps:
1. Run composer to install the bundle, 
2. configure your security configuration and
3. create a htpasswd password storage file.

All available password formats [of the basic authentication](https://httpd.apache.org/docs/2.4/howto/auth.html) are supported: `apr1-md5`, `bcrypt`, `crypt`, `sha1` and plain text - see
http://httpd.apache.org/docs/current/misc/password_encryptions.html.

## Table of Contents

* [Requirements](#requirements)
* [Integration & Basic Usage](#integration--basic-usage)
  * [Installation](#installation)
  * [Symfony Configuration](#symfony-configuration)
  * [Add Htpasswd File](#add-htpasswd-file)
* [Advanced Usage & Configuration](#advanced-usage--configuration)
  * [Change Location of Your Htpasswd File](#change-location-of-your-htpasswd-file)
  * [Change Default User Roles](#change-default-user-roles)
  * [User Roles Inside Htpasswd File](#user-roles-inside-htpasswd-file)
* [Credits](#credits)
  
## Requirements

The usage of [**PHP v7.2**](https://www.php.net/manual/en/migration72.new-features.php) 
and [**Symfony 4**](https://symfony.com/doc/4.0/setup.html) is obligatory.


     

## Integration & Basic Usage

### Installation

Please install via [composer](https://getcomposer.org/).

```bash
composer require prokki/htpasswd "^0.0"
```

The bundle will be automatically added to your `bundles.yaml` configuration.

### Symfony Configuration

To enable the functionality you have to change your security configuration manually.

1. Enable the provider [HtpasswdUserProvider](src/Security/HtpasswdUserProvider.php)
   and the encoder [HtpasswdEncoder](src/Security/HtpasswdEncoder.php)
   in your security configuraton, i.e. in your
   `%kernel.project_dir%/config/security.yaml` file.
 2. To enable http basic authentication add the `http_basic` authentication method
    to the firewall configuration. 
 3. Additionally be sure to enable **access_control** for at least one path.

**`security.yaml`**:
```yaml
security:

  # 1.a) add the HtpasswdUserProvider as a new provider (the name does not matter)
  providers:
    bz_map_cycle_provider:
      id: Htpasswd\Security\HtpasswdUserProvider

  # 1.b) and add the HtpasswdEncoder as a new encoder (the name does not matter)
  encoders:
    Symfony\Component\Security\Core\User\User:
      id: Htpasswd\Security\HtpasswdEncoder

  # 2. enable basic authentication
  firewalls:
    main:
      http_basic: ~
      
  # 3. be sure to add one path
  access_control:
    - { path: ^/, roles: ROLE_USER }
```

Feel free to use the full flexibility of the Symfoniy security layer which means
i.e. you can

- chain firewalls,
- add other providers and encoders,
- restrict basic authentication to certain paths only
- etc.

### Add Htpasswd File

Create your custom htpasswd file using the [htpasswd](https://httpd.apache.org/docs/2.4/programs/htpasswd.html) command in the
project directory of your project.

Hint: Usually the command is installed automatically if you run an [apache](https://httpd.apache.org/) web server, i.e. if you use
[xampp](https://www.apachefriends.org/) or your package management system.
On linux systems the command is mostly provided by the package `apache2-utils`. 

Create a htpasswd file in your project directory.
Call the following command and type in  your password:
  
```bash
htpasswd -cB .htpasswd admin
```

A new file was created in your project:
```
%kernel.project_dir%/
  - config/
    - packages/
      - security.yaml   <-- do not forget to change your configuration
    - bundles.yaml
    - services.yaml
  - src/
    - Controller/
    - Entity/
    - Service/
    - [...]
  - tests/
  - composer.json
  - .htpasswd           <-- new htpasswd file in your project directory
```

:warning: For safety reasons we suggest to not include the htpasswd file in your repository! 

## Advanced Usage & Configuration

You are not really able to change the configuration of the bundle, but at least
you can customize the location of your htpasswd file and the default user roles.

In both cases you have to create a new configuratio file **`htpasswd.yaml`** for the bundle:
```
%kernel.project_dir%/
  - config/
    - packages/
      - security.yaml
      - htpasswd.yaml   <-- custom configuration file
```

The default content of the file should look like following. If you just insert these
configuration, the bundle works with default settings.
```yaml
htpasswd:
  path: ~       # the path of your htpasswd file, ie. "%kernel.project_dir%/public/passwords.txt" 
  roles: ~      # the default roles of each basic auth user
```

### Change Location of Your Htpasswd File

It is possible to change the default location by changing the `path` variable.

This is useful if you use your htpasswd file in other projects or if you set up
a basic authentication additionally via your apache2 configuration.

```yaml
htpasswd:
  path: "/etc/apache2/.htpasswd" 
  roles: ~
```

### Change Default User Roles

The default user role assigned to each user
(included by the [HtpasswdUserProvider](src/Security/HtpasswdUserProvider.php))
is *ROLE_USER*.
To change the default user roles, adapt the `roles` variable in the configuration:
```yaml
htpasswd:
  path: ~ 
  roles: ["ROLE_ADMIN", "ROLE_ALLOW_WRITE", ...]
```

If you change the `roles` config parameter, be sure to include all roles which are necessary.
There is no process to add another default user role. 

Additionally please take care, that the roles 
1. follow the recommendations of [symfony user roles](https://symfony.com/doc/current/security.html#roles) and
2. match the *access_control* settings in your `security.yaml` file.



## User Roles Inside Htpasswd File

The implementation of the basic authentication allows you to add user roles
at the end of each line in the htpasswd file.

Similar to overwriting the user roles by configuration, be sure to
1. follow the recommendations of [symfony user roles](https://symfony.com/doc/current/security.html#roles) and
2. match the *access_control* settings in your `security.yaml` file.

The user roles are a comma-separated list which are separated from the origin line by a colon. Example:
```
user:$2y$05$G0q46R6tXNYmGnwHK74hyuUsz.IlCoVoOlMLjuLdgi.hWvwuqAr8G:ROLES_A,ROLES_B,ROLES_C
```
  

:warning: This feature is probably not supported by all platforms!

Content of a well-structured htpasswd file:
```
# encoded by bcrypt, pass: admin1
admin1:$apr1$j0jl5669$vMiAX1Dxz4li8GACC0bJ1/

# encoded by apr1-md5, pass: admin2
admin2:$2y$05$.im1AvKvAVUTl6rlbY8ycu8iz6Q3.BhMsrZVVZb.agFCQ0u1aTzKa

# encoded by crypt, pass: admin3
admin3:WArkJFYVv3SDU

# encoded by sha1, pass: admin4
admin4:{SHA}6gU9Eaiq0cz4wY+SQbrrnsR+XWQ=

# not encoded / plain text
admin5:admin5
```

Content of a htpasswd file with additional user roles:
```
# encoded by bcrypt, pass: admin1, user roles ROLE_USER and ROLE_ADMIN
admin1:$apr1$j0jl5669$vMiAX1Dxz4li8GACC0bJ1/:ROLE_USER,ROLE_ADMIN

# encoded by apr1-md5, pass: admin2, user roles ROLE_USER and ROLE_SUPERVISOR
admin2:$2y$05$.im1AvKvAVUTl6rlbY8ycu8iz6Q3.BhMsrZVVZb.agFCQ0u1aTzKa:ROLE_USER,ROLE_SUPERVISOR

# encoded by crypt, pass: admin3, user roles ROLE_READ_ONLY
admin3:WArkJFYVv3SDU:ROLE_READ_ONLY

# encoded by sha1, pass: admin4, user roles ROLE_USER and ROLE_ADMIN
admin4:{SHA}6gU9Eaiq0cz4wY+SQbrrnsR+XWQ=:ROLE_USER,ROLE_ADMIN

# not encoded / plain text
admin5:admin5
```

## Credits

A big thank you to [https://github.com/whitehat101](https://github.com/whitehat101/apr1-md5) for the implementation of the `apr1-md5` algorithm.
 