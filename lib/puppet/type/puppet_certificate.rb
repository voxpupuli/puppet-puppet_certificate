Puppet::Type.newtype(:puppet_certificate) do
  @doc = "Manage Puppet certificates"
  desc <<-EOT
    Ensures that a given Puppet certificate exists or does not exist.
  EOT

  ensurable

  newparam(:name) do
    isnamevar
    isrequired
    desc "The certificate name"
  end

  newparam(:ca_location) do
    desc "The location of the certificate authority (local or remote)"
  end

  newparam(:ca_server) do
    desc "The certificate authority to use"
  end

  newparam(:waitforcert) do
    desc "The amount of time to wait for the certificate to be signed"
  end

  newproperty(:dns_alt_names, :array_matching => :all) do
    desc "Alternate DNS names by which the certificate holder may be reached"
  end

end
