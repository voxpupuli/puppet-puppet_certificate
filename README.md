# Puppet Certificate #

Manage Puppet certificates as resources. E.g.

    puppet_certificate { 'puppetmaster07.example.com':
      ensure        => present,
      dns_alt_names => [
        'puppet',
        'puppet.example.com',
      ],
    }

    puppet_certificate { 'oldcert.example.com':
      ensure => absent,
    }
