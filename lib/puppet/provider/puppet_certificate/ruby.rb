Puppet::Type.type(:puppet_certificate).provide(:ruby) do
  desc "Manage Puppet certificates using the certificate face"

  def create
    debug "create #{@resource[:name]}"
    generate_certificate
    retreive_certificate
  end

  def generate_certificate
    unless private_key_exists?
      debug "generating new certificate for #{@resource[:name]}"
      Puppet::Face[:certificate, '0.0.1'].generate(@resource[:name], options)
    end
  end

  def retreive_certificate
    unless certificate_exists?
      debug "retreiving certificate for #{@resource[:name]}"
      cert = Puppet::Face[:certificate, '0.0.1'].find(@resource[:name], options)
      fail(<<-EOL.gsub(/\s+/, " ").strip) unless cert
        unable to retreive certificate for #{@resource[:name]}. You may need
        to sign this certificate on the CA host by running `puppet certificate
        sign #{@resource[:name]} --ca-location=local --mode=master`
      EOL
    end
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
    debug "checking to see if private key exists for #{@resource[:name]}"
    ssldir  = Puppet.settings[:ssldir]
    keyname = "#{@resource[:name]}.pem"
    exists = ['private_keys'].all? do |elem|
      File.exists?(File.join(ssldir, elem, keyname))
    end
    debug "private key exists for #{@resource[:name]}: #{exists}"
    exists
  end

  def certificate_exists?
    debug "checking to see if certificate exists for #{@resource[:name]}"
    ssldir  = Puppet.settings[:ssldir]
    keyname = "#{@resource[:name]}.pem"
    exists  = ['certs'].all? do |elem|
      File.exists?(File.join(ssldir, elem, keyname)) \
        and not File.zero?(File.join(ssldir, elem, keyname))
    end
    debug "certificate exists for #{@resource[:name]}: #{exists}"
    exists
  end

  def debug(msg)
    Puppet.debug "puppet_certificate: #{msg}"
  end

end
