Puppet::Type.type(:puppet_certificate).provide(:ruby) do
  desc "Manage Puppet certificates using the certificate face"

  def create
    debug "create #{@resource[:name]}"
    generate_key
    submit_csr
    if ca_location == 'local'
      sign_certificate
    else
      retreive_certificate
    end
  end

  def generate_key
    unless key
      debug "generating new key for #{@resource[:name]}"
      Puppet::Face[:certificate, '0.0.1'].generate(@resource[:name], options)
    end
  end

  def submit_csr
    # Not implemented. Maybe it would look something like
    # Puppet::SSL::CertificateRequest.indirection.save(csr)
  end

  def retreive_certificate
    unless certificate
      debug "retreiving certificate for #{@resource[:name]}"
      cert = Puppet::Face[:certificate, '0.0.1'].find(@resource[:name], options)

      # If a cert didn't result then fail verbosely
      fail(<<-EOL.gsub(/\s+/, " ").strip) unless cert
        unable to retreive certificate for #{@resource[:name]}. You may need
        to sign this certificate on the CA host by running `puppet certificate
        sign #{@resource[:name]} --ca-location=local --mode=master`
      EOL

    end
  end

  def sign_certificate
    unless certificate
      debug "signing certificate for #{@resource[:name]}"
      begin
        opts = options.merge(:allow_dns_alt_names => true)
        cert = Puppet::Face[:certificate, '0.0.1'].sign(@resource[:name], opts)
      rescue Exception => e
        raise e unless e.message.match(/not configured as a certificate auth/)
        # The face fails us. Do it oldskool.
        ca = Puppet::SSL::CertificateAuthority.new
        interface = Puppet::SSL::CertificateAuthority::Interface.new(
          :sign,
          opts.merge({:to => [@resource[:name]]})
        )
        cert = interface.sign(ca)
      end

      # If a cert didn't result then fail verbosely
      fail(<<-EOL.gsub(/\s+/, " ").strip) unless cert
        unable to sign certificate for #{@resource[:name]}
      EOL

    end
  end

  def destroy
    Puppet::SSL::Key.indirection.destroy(@resource[:name])
    Puppet::SSL::Certificate.indirection.destroy(@resource[:name])
    Puppet::SSL::CertificateRequest.indirection.destroy(@resource[:name])
  end

  def exists?
    case @resource[:ensure]
    when :absent, 'absent'
      key
    else
      key and certificate
    end
  end

  def dns_alt_names
    # not implemented
    @resource[:dns_alt_names]
  end

  def dns_alt_names=(should_dns_alt_names)
    # not implemented
  end

  def ca_location
    @ca_location ||= begin
      if @resource[:ca_location]
        @resource[:ca_location]
      else
        case Puppet.settings[:ca_server]
        when Facter.value('fqdn'), Facter.value('hostname')
          'local'
        else
          'remote'
        end
      end
    end
  end

  def options
    @options ||= begin
      options = {}
      options[:ca_location] = ca_location
      if @resource[:dns_alt_names]
        options[:dns_alt_names] = @resource[:dns_alt_names].join(',')
      end
      options
    end
  end

  def key
    @key ||= Puppet::SSL::Key.indirection.find(@resource[:name])
  end

  def certificate
    @certificate ||= Puppet::SSL::Certificate.indirection.find(@resource[:name])
  end

  def csr
    @csr ||= begin
      @csr = Puppet::SSL::CertificateRequest.indirection.find(@resource[:name])
      unless @csr
        @csr = Puppet::SSL::CertificateRequest.new(@resource[:name])
        @csr.generate(key.content, options)
      end
    end
  end

  def debug(msg)
    Puppet.debug "puppet_certificate: #{msg}"
  end

end