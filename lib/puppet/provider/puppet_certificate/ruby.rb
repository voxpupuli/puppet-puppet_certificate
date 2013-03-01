Puppet::Type.type(:puppet_certificate).provide(:ruby) do
  desc "Manage Puppet certificates using the certificate face"

  def create
    generate_certificate
    retreive_certificate
  end

  def generate_certificate
    unless certificate_exists? do
      Puppet::Face[:certificate, '0.0.1'].generate(@resource[:name], options)
    end
  end

  def retreive_certificate
    Puppet::Face[:certificate, '0.0.1'].find(@resource[:name], options)
  end

  def delete
    nil
  end

  def exists?
    private_key_exists? and certificate_exists?
  end

  def dns_alt_names
    nil
  end

  def dns_alt_names=(should_dns_alt_names)
    nil
  end

  def ca_location
    @ca_location ||= case Puppet.settings[:ca]
    when true, 'true'
      'local'
    when false, 'false'
      'remote'
    end
  end

  def options
    @options ||= begin
      options = {}
      options[:ca_location] = ca_location
      if @resource[:dns_alt_names]
        options[:dns_alt_names] = @resource[:dns_alt_names]
      end
      options
    end
  end

  def private_key_exists?
    ssldir  = Puppet.settings[:ssldir]
    keyname = "#{@resource[:name]}.pem"
    ['private_keys'].all? do |elem|
      File.exists?(File.join(ssldir, elem, keyname))
    end
  end

  def certificate_exists?
    ssldir  = Puppet.settings[:ssldir]
    keyname = "#{@resource[:name]}.pem"
    ['certs'].all? do |elem|
      File.exists?(File.join(ssldir, elem, keyname))
    end
  end

end
