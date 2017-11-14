require 'fileutils'
require 'puppet/face'

Puppet::Type.type(:puppet_certificate).provide(:ruby) do
  desc "Manage Puppet certificates using the certificate face"

  def create
    debug "create #{@resource[:name]}"
    generate_key
    submit_csr
    if ca_location == 'local'
      sign_certificate
    else
      retrieve_certificate
    end
  end

  def generate_key
    unless key
      debug "generating new key for #{@resource[:name]}"
      ensure_cadir if ca_location == 'local'
      Puppet::SSL::Oids.register_puppet_oids
      Puppet::Face[:certificate, '0.0.1'].generate(@resource[:name], options)
    end
  end

  def submit_csr
      # Actually not required, generation submits CSR automatically
      #begin
      #    Puppet::SSL::CertificateRequest.indirection.save(csr)
      #rescue ArgumentError
      #end
  end

  def retrieve_certificate
    unless certificate
      timeout = 0
      certname = @resource[:name]
      debug "retrieving certificate for #{certname}"
      if @resource[:waitforcert]
        timeout = @resource[:waitforcert].to_i
      end

      cert = Puppet::Face[:certificate, '0.0.1'].find(certname, options)
      return if cert

      if timeout != 0
        alert(<<-EOL.gsub(/\s+/, " ").strip)
          Waiting #{timeout} seconds for #{certname} to be signed. Please
          sign this certificate on the CA host or use the Request Manager
          in the Puppet Enterprise Console.
        EOL

        while timeout > 0 && cert.nil?
          cert = Puppet::Face[:certificate, '0.0.1'].find(certname, options)
          sleep 1 # trying every second might be a bit too rapid?
          timeout -= 1
        end
      end

      # If a cert didn't result then fail verbosely
      fail(<<-EOL.gsub(/\s+/, " ").strip) unless cert
        unable to retrieve certificate for #{@resource[:name]}. You may need
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
        ensure_cadir
        cert = interface.sign(ca)
      end

      # If a cert didn't result then fail verbosely
      fail(<<-EOL.gsub(/\s+/, " ").strip) unless cert
        unable to sign certificate for #{@resource[:name]}
      EOL

    end
  end

  def ensure_cadir
    # This makes everything "just work" even on systems without a cadir yet
    cadir = Puppet.settings[:cadir]
    if not File.exists?(cadir)
      FileUtils.mkdir_p(File.join(cadir, 'requests'), :mode => 0750)
      FileUtils.chown_R(Puppet.settings[:user], Puppet.settings[:group], cadir)
    end
  end

  def destroy
    Puppet::SSL::Key.indirection.destroy(@resource[:name])
    @key = nil
    Puppet::SSL::Certificate.indirection.destroy(@resource[:name])
    @certificate = nil
    Puppet::SSL::CertificateRequest.indirection.destroy(@resource[:name])
    @csr = nil
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
      @csr
    end
  end

  def is_valid?
      unless certificate.nil?
          grace_time = @resource[:renewal_grace_period] * 60 * 60 * 24
          certificate.content.not_after - grace_time > Time.now
      end
  end

  def debug(msg)
    Puppet.debug "puppet_certificate: #{msg}"
  end

end
