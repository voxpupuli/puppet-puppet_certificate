# Puppet Certificate #

## Summary

Manage Puppet certificates as resources using the `puppet_certificate` type.

## Usage

Example:

```puppet
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
```

## Advanced features

### Refresh

When refreshed (notify, subscribe) a puppet\_certificate resource will destroy
and re-create the managed certifiate. This enables changes to related resources
to trigger a certificate to be regenerated.

To enable this functionality, you *must* set the onrefresh parameter to
`regenerate`. Otherwise, the resource will not respond to refresh events.

Note that for this to work as expected, it will need to be combined with
automatic certificate cleaning (described in a following section).

```puppet
file { '/etc/puppetlabs/puppet/csr_attributes.yaml':
  ensure  => file,
  owner   => 'root',
  group   => 'root',
  mode    => '0440',
  content => epp('example/csr_attributes.yaml.epp'),
} ~>

puppet_certificate { $certname:
  ensure      => present,
  waitforcert => 60,
  onrefresh   => regenerate,
}
```

### Ensure valid

Besides `ensure=present`, a puppet\_certificate may be set to `ensure=valid`.
When configured this way, if the Puppet certificate has expired, it will be
destroyed and a new certificate created. Note that this does not automatically
handle signing of the new certificate, or cleanup of the old (expired)
certificate.

The renewal\_grace\_period parameter may be combined with `ensure=valid` to
perform certificate regeneration a configurable number of days before a
certificate is due to expire.

```puppet
puppet_certificate { $certname:
  ensure               => valid,
  renewal_grace_period => 20,
}
```

### Automatic certificate cleaning

The `clean` parameter tells a puppet\_certificate to try and clean a
certificate from the CA upon destroying it.

This is useful to keep the CA clean, and as a prerequisite action for
generating a new certificate of the same name. To use this option effectively,
it is required that a rule be added to auth.conf on the CA to allow this. For
example, to allow nodes to revoke and clean their own certificates.

Example auth.conf rule:

```
{
    name: "Allow nodes to delete their own certificates",
    match-request: {
        path: "^/puppet-ca/v1/certificate(_status|_request)?/([^/]+)$",
        type: regex,
        method: [delete]
    },
    allow: "$2",
    sort-order: 500
}
```

```puppet
puppet_certificate { $certname:
  ensure               => valid,
  waitforcert          => 60,
  renewal_grace_period => 20,
  clean                => true,
}
```

## Reference

## Contributors

* Reid Vandewiele
* Branan Riley
* Raphaël Pinson
