<?php

namespace Htpasswd\DependencyInjection;

use Htpasswd\Exception\FileNotReadableException;
use Exception;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\Filesystem\Exception\FileNotFoundException;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader;
use Symfony\Component\Config\FileLocator;
use function array_filter;
use function array_merge;
use function sprintf;

/**
 *
 * @link    http://symfony.com/doc/current/bundles/extension.html
 *
 * @package Htpasswd
 */
class HtpasswdBundleExtension extends Extension
{
    /**
     * {@inheritDoc}
     */
    public function getAlias(): string
    {
        return 'Htpasswd';
    }

    /**
     * {@inheritDoc}
     *
     * @throws Exception
     */
    public function load(array $configs, ContainerBuilder $container)
    {
        /** @var LoaderInterface $loader */
        $loader = new Loader\YamlFileLoader($container, new FileLocator(__DIR__ . '/../Resources/config'));
        $loader->load('services.yml');

        // create a default config
        $defaultConfig = $this->getDefaultConfig($container);

        // override parameters
        $config = array_merge(
            $defaultConfig,
            // remove null values from read config
            array_filter($this->processConfiguration(new Configuration(), $configs))
        );

        // and check config
        $this->checkConfig($config);

        $container->setParameter('Htpasswd.path', $config[ 'path' ]);
        $container->setParameter('Htpasswd.roles', $config[ 'roles' ]);
    }

    protected function getDefaultConfig(ContainerBuilder $container): array
    {
        return array(
            'path' => sprintf('%s%s%s', $container->getParameter('kernel.project_dir'), DIRECTORY_SEPARATOR, '.htpasswd'),
        );
    }

    /**
     * @param mixed[] $config
     *
     * @throws FileNotFoundException
     * @throws FileNotReadableException
     */
    protected function checkConfig(array $config)
    {
        if( !is_file($config[ 'path' ]) )
        {
            throw new FileNotFoundException(null, 0, null, $config[ 'path' ]);
        }

        if( !is_readable($config[ 'path' ]) )
        {
            throw new FileNotReadableException(null, 0, null, $config[ 'path' ]);
        }
    }

}
