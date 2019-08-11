<?php

namespace Htpasswd;

use Htpasswd\DependencyInjection\HtpasswdBundleExtension;
use Symfony\Component\HttpKernel\Bundle\Bundle;

/**
 * Class HtpasswdUserProviderBundle
 *
 * @link http://httpd.apache.org/docs/current/misc/password_encryptions.html
 */
class HtpasswdBundle extends Bundle
{
    /**
     * {@inheritDoc}
     */
    public function boot()
    {
        $this->name = 'Htpasswd';
        parent::boot();
    }

    /**
     * {@inheritDoc}
     */
    public function getContainerExtension()
    {
        return new HtpasswdBundleExtension();
    }
}
