require 'fileutils'
require 'puppet/face'
require 'puppet/ssl/certificate'

Puppet::Type.type(:puppet_certificate).provide(:ruby) do
  desc "Manage Puppet certificates using the certificate face"

  def create
    debug "create #{@resource[:name]}"
    generate_csr
    if ca_location == 'local'
      sign_certificate
    else
      retrieve_certificate
    end
  end

  def generate_csr
    unless key
      debug "generating new key for #{@resource[:name]}"
      ensure_cadir if ca_location == 'local'
      Puppet::SSL::Oids.register_puppet_oids if Puppet::SSL::Oids.respond_to?('register_puppet_oids')
      host = Puppet::SSL::Host.new(@resource[:name])
      host.generate_certificate_request(:dns_alt_names => options[:dns_alt_names])
    end
  end

  def retrieve_certificate
    unless certificate
      @machine = Puppet::SSL::StateMachine.new
      ssl_context = @machine.ensure_ca_certificates

      timeout = 0
      certname = @resource[:name]
      debug "retrieving certificate for #{certname}"
      if @resource[:waitforcert]
        timeout = @resource[:waitforcert].to_i
      end

      cert = download_cert(ssl_context)

      if cert.nil? && timeout != 0
        notice(<<-EOL.gsub(/\s+/, " ").strip)
          Waiting #{timeout} seconds for #{certname} to be signed. Please
          sign this certificate on the CA host or use the Request Manager
          in the Puppet Enterprise Console.
        EOL

        while timeout > 0 && cert.nil?
          cert = download_cert(ssl_context)
          sleep 2 # trying every second might be a bit too rapid?
          timeout -= 1
        end
      end

      # If a cert didn't result then fail verbosely
      fail(<<-EOL.gsub(/\s+/, " ").strip) unless cert
        unable to retrieve certificate for #{@resource[:name]}. You may need
        to sign this certificate on the CA host by running `puppet certificate
        sign #{@resource[:name]} --ca-location=local --mode=master`
      EOL

      @ssl_provider = Puppet::SSL::SSLProvider.new
      @cert_provider = Puppet::X509::CertProvider.new
      @ssl_provider.create_context(
        cacerts: ssl_context.cacerts,
        crls: ssl_context.crls,
        private_key: key,
        client_cert: cert
      )
      @cert_provider.save_client_cert(@resource[:name], cert)
      @cert_provider.delete_request(@resource[:name])
    end
  end

  def sign_certificate
    unless certificate
      debug "signing certificate for #{@resource[:name]}"
      opts = options.merge(:allow_dns_alt_names => true)
      # Do it oldskool.
      ca = Puppet::SSL::CertificateAuthority.new
      interface = Puppet::SSL::CertificateAuthority::Interface.new(
        :sign,
        opts.merge({:to => [@resource[:name]]})
      )
      ensure_cadir
      cert = interface.sign(ca)

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

  def clean
      debug "cleaning #{@resource[:name]} on ca"
      req = Net::HTTP::Delete.new("/puppet-ca/v1/certificate_status/#{@resource[:name]}")
      https = Net::HTTP.new(Puppet.settings[:ca_server], Puppet.settings[:ca_port])
      https.use_ssl = true
      https.cert = OpenSSL::X509::Certificate.new(File.read(Puppet.settings[:hostcert]))
      https.key = OpenSSL::PKey::RSA.new(File.read(Puppet.settings[:hostprivkey]))
      https.verify_mode = OpenSSL::SSL::VERIFY_PEER
      https.ca_file = Puppet.settings[:localcacert]
      resp = https.start { |cx| cx.request(req) }
      if resp.code_type != Net::HTTPNoContent
          warning "failed to clean certificate: #{resp.body}"
      end
  end

  def destroy
    if @resource[:clean]
        clean
    end

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
    @cert_provider = Puppet::X509::CertProvider.new
    @key ||= @cert_provider.load_private_key(@resource[:name])
  rescue NameError
    # Older versions of Puppet (before 6.4?) don't have Puppet::X509
    # so use the old way of getting the key.
    # Not tested, but presumably this means versions 6.x before 6.4
    # aren't going to work right now??
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

  # Create/return a store that uses our SSL info to validate
  # connections.
  def ssl_store(purpose = OpenSSL::X509::PURPOSE_ANY)
    if @ssl_store.nil?
      @ssl_store = build_ssl_store(purpose)
    end
    @ssl_store
  end

  def build_ssl_store(purpose=OpenSSL::X509::PURPOSE_ANY)
    store = OpenSSL::X509::Store.new
    store.purpose = purpose

    # Use the file path here, because we don't want to cause
    # a lookup in the middle of setting our ssl connection.
    store.add_file(Puppet.settings[:localcacert])

    if use_crl?
      if !Puppet::FileSystem.exist?(crl_path)
        download_and_save_crl_bundle(store)
      end

      crls = load_crls(crl_path)

      flags = OpenSSL::X509::V_FLAG_CRL_CHECK
      if use_crl_chain?
        flags |= OpenSSL::X509::V_FLAG_CRL_CHECK_ALL
      end

      store.flags = flags
      crls.each {|crl| store.add_crl(crl) }
    end
    store
  end

  def use_crl?
    !!@crl_usage
  end

  def use_crl_chain?
    @crl_usage == true || @crl_usage == :chain
  end

  def download_cert(ssl_context)
    route = create_route(ssl_context)
    Puppet.info _("Downloading certificate '%{name}' from %{url}") % { name: @resource[:name], url: route.url }
    _, x509 = route.get_certificate(@resource[:name], ssl_context: ssl_context)
    cert = OpenSSL::X509::Certificate.new(x509)
    Puppet.notice _("Downloaded certificate '%{name}' with fingerprint %{fingerprint}") % { name: @resource[:name], fingerprint: fingerprint(cert) }
    cert
  rescue Puppet::HTTP::ResponseError => e
    if e.response.code == 404
      return nil
    else
      raise Puppet::Error.new(_("Failed to download certificate: %{message}") % { message: e.message }, e)
    end
  rescue => e
    raise Puppet::Error.new(_("Failed to download certificate: %{message}") % { message: e.message }, e)
  end

  def debug(msg)
    Puppet.debug "puppet_certificate: #{msg}"
  end

  def fingerprint(cert)
    Puppet::SSL::Digest.new(nil, cert.to_der)
  end

  def create_route(ssl_context)
    Puppet.runtime[:http].create_session.route_to(:ca, ssl_context: ssl_context)
  end

end
