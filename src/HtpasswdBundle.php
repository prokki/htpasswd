<?php

namespace Htpasswd;

use Prokki\Htpasswd\DependencyInjection\HtpasswdBundleExtension;
use Symfony\Component\DependencyInjection\Extension\ExtensionInterface;
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
    public function getContainerExtension(): ?ExtensionInterface
    {
        return new HtpasswdBundleExtension();
    }
}
