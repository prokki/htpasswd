<?php

namespace Htpasswd;

use Htpasswd\DependencyInjection\HtpasswdBundleExtension;
use Symfony\Component\HttpKernel\Bundle\Bundle;

/**
 * Class HtpasswdBundle
 *
 * @package Htpasswd
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
