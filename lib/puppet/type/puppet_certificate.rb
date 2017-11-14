Puppet::Type.newtype(:puppet_certificate) do
  @doc = "Manage Puppet certificates"
  desc <<-EOT
    Ensures that a given Puppet certificate exists or does not exist.
  EOT

  ensurable do
      desc "Create or remove the Puppet certificate"
      defaultvalues
      block if block_given?

      newvalue(:valid) do
          if provider.exists?
              if provider.is_valid?
                  if @resource.property(:dns_alt_names)
                      @resource.property(:dns_alt_names).sync
                  end
              else
                  provider.destroy
                  provider.create
              end
          else
              provider.create
          end
      end

      def insync?(is)
          return true if should == :valid and provider.is_valid?
          super
      end
  end

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

  newparam(:renewal_grace_period) do
    desc "The number of days before expiration the certificate should be renewed"
    munge do |v|
        Integer(v)
    end
    defaultto(0)
  end

  newparam(:clean, :boolean => true) do
    desc "Delete the certificate from the CA before removing it locally."

    defaultto :false
  end

  newparam(:onrefresh) do
    desc "If set to 'regenerate', a refresh event will cause the certificate to be destroyed and recreated."
    newvalues(:regenerate, :nothing)

    defaultto :nothing
  end

  newproperty(:dns_alt_names, :array_matching => :all) do
    desc "Alternate DNS names by which the certificate holder may be reached"
  end

  def refresh
    if [:present, :valid].include?(@parameters[:ensure].value) &&
      @parameters[:onrefresh].value == :regenerate

      provider.destroy
      provider.create
    end
  end
end
