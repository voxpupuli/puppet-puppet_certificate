# Puppet Certificate

[![Build Status](https://github.com/voxpupuli/puppet-puppet_certificate/workflows/CI/badge.svg)](https://github.com/voxpupuli/puppet-puppet_certificate/actions?query=workflow%3ACI)
[![Release](https://github.com/voxpupuli/puppet-puppet_certificate/actions/workflows/release.yml/badge.svg)](https://github.com/voxpupuli/puppet-puppet_certificate/actions/workflows/release.yml)
[![Puppet Forge](https://img.shields.io/puppetforge/v/puppet/puppet_certificate.svg)](https://forge.puppetlabs.com/puppet/puppet_certificate)
[![Puppet Forge - downloads](https://img.shields.io/puppetforge/dt/puppet/puppet_certificate.svg)](https://forge.puppetlabs.com/puppet/puppet_certificate)
[![Puppet Forge - endorsement](https://img.shields.io/puppetforge/e/puppet/puppet_certificate.svg)](https://forge.puppetlabs.com/puppet/puppet_certificate)
[![Puppet Forge - scores](https://img.shields.io/puppetforge/f/puppet/puppet_certificate.svg)](https://forge.puppetlabs.com/puppet/puppet_certificate)
[![Apache-2 License](https://img.shields.io/github/license/voxpupuli/puppet-puppet_certificate.svg)](LICENSE)
[![Donated by Reid Vandewiele](https://img.shields.io/badge/donated%20by-Reid%20Vandewiele-fb7047.svg)](#transfer-notice)

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
and re-create the managed certificate. This enables changes to related resources
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

Puppet Enterprise already has a rule for this API. You cannot have multiple
blocks in auth.conf for the same path. Therefore you need to patch
`/opt/puppetlabs/puppet/modules/puppet_enterprise/manifests/profile/certificate_authority.pp`

```diff
# git diff --no-index /tmp/certificate_authority.pp
/opt/puppetlabs/puppet/modules/puppet_enterprise/manifests/profile/certificate_authority.pp
diff --git a/tmp/certificate_authority.pp
b/opt/puppetlabs/puppet/modules/puppet_enterprise/manifests/profile/certificate_authority.pp
index ba4de6b..4c71dd5 100644
--- a/tmp/certificate_authority.pp
+++ b/opt/puppetlabs/puppet/modules/puppet_enterprise/manifests/profile/certificate_authority.pp
@@ -99,10 +99,10 @@ class puppet_enterprise::profile::certificate_authority (

   pe_puppet_authorization::rule { 'puppetlabs certificate status':
     ensure               => present,
-    match_request_path   => '/puppet-ca/v1/certificate_status/',
-    match_request_type   => 'path',
+    match_request_path   => '^/puppet-ca/v1/certificate_status/([^/]+)?$',
+    match_request_type   => 'regex',
     match_request_method => ['get','put','delete'],
-    allow                => $_client_allowlist << $ca_cli_extension,
+    allow                => ['$1', $_client_allowlist].flatten << $ca_cli_extension,
     sort_order           => 500,
     path                 => '/etc/puppetlabs/puppetserver/conf.d/auth.conf',
     notify               => Service['pe-puppetserver'],
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

## Transfer Notice

This module was originally authored by [Reid Vandewiele](http://github.com/reidmv).
The maintainer preferred that [Vox Pupuli](https://voxpupuli.org/) take ownership of the module for future improvement and maintenance.

Existing pull requests and issues were transferred over.
Please fork and continue to contribute [here](https://github.com/voxpupuli/puppet-puppet_certificate) instead of the
module's original [home](https://github.com/reidmv/puppet-puppet_certificate).
