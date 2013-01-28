define puppet_certificate (
  $certname      = $title,
  $ssldir        = $::settings::ssldir,
  $ca_location   = 'remote',
  $mode          = 'agent',
  $dns_alt_names = undef
) {

  # Depending on whether the CA is local or remote, choose whether to sign
  # the new cert or just try to request it from the remote CA when it's time
  # to "get" the certificate.
  case $ca_location {
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
      fail("unsupported ca_location ${ca_location}")
    }
  }

  $request_file    = "$ssldir/certificate_requests/$certname.pem"
  $key_file        = "$ssldir/private_keys/$certname.pem"
  $cert_file       = "$ssldir/certs/$certname.pem"
  $get_options     = "--ca-location $ca_location --mode $get_mode $certname"
  $request_options = $dns_alt_names ? {
    undef   => "--ca-location $ca_location --mode $mode $certname",
    default => "--ca-location $ca_location --mode $mode --dns-alt-names $dns_alt_names $certname",
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
