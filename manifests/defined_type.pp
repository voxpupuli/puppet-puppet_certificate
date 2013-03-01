define puppet_certificate::defined_type (
  $certname      = $title,
  $ssldir        = $::settings::ssldir,
  $ca_location   = undef,
  $mode          = 'agent',
  $dns_alt_names = undef,
  $ca_server     = hiera('puppet_certificate::ca_server', $::settings::ca_server),
) {

  # If local/remote ca_server wasn't explicitely specified, figure it out
  if !$ca_location {
    case $ca_server {
      $::fqdn, $::hostname: { $use_location = 'local'  }
      default: { $use_location = 'remote' }
    }
  }

  # Depending on whether the CA is local or remote, choose whether to sign
  # the new cert or just try to request it from the remote CA when it's time
  # to "get" the certificate.
  case $use_location {
    'remote': {
      $get_mode    = $mode
      $get_command = 'find'
    }
    'local': {
      $get_mode    = 'master'
      $get_command = $dns_alt_names ? {
        undef   => 'sign',
        default => 'sign --allow-dns-alt-names',
      }
    }
    default: {
      fail("unsupported ca_location ${use_location}")
    }
  }

  $ca_server_options = $ca_server ? {
    default => "--ca_server $ca_server",
    undef   => '',
  }
  $request_file      = "$ssldir/certificate_requests/$certname.pem"
  $key_file          = "$ssldir/private_keys/$certname.pem"
  $cert_file         = "$ssldir/certs/$certname.pem"
  $common_options    = "--ca-location $use_location $ca_server_options --certname $::clientcert"
  $get_options       = "$common_options --mode $get_mode $certname"
  $request_options   = $dns_alt_names ? {
    undef   => "$common_options --mode $mode $certname",
    default => "$common_options --mode $mode --dns-alt-names $dns_alt_names $certname",
  }

  Exec {
    logoutput => on_failure,
    path      => '/opt/puppet/bin:/usr/bin:/bin:/usr/sbin:/sbin',
  }

  exec { "cert_request_for_$title":
    command => "puppet certificate generate $request_options",
    unless  => "test -s $cert_file -o -s $key_file",
  } ->
  exec { "get_cert_for_$title":
    command  => "puppet certificate $get_command $get_options && test -s $cert_file",
    unless   => "test -s $cert_file",
    provider => shell,
  }

}
