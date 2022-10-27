require 'fileutils'
require 'puppet/face'
require 'puppet/ssl/certificate'

Puppet::Type.type(:puppet_certificate).provide(:ruby) do
  desc 'Manage Puppet certificates'

  def initialize(value = {})
    super(value)
    if at_least_puppet6
      @cert_provider = Puppet::X509::CertProvider.new(hostprivkey: nil, hostcert: nil)
      @machine = Puppet::SSL::StateMachine.new
    else
      debug('using legacy code and APIs')
    end
  end

  def create
    debug "create #{@resource[:name]}"
    submit_csr
    sign_certificate if @resource[:ca_location] == :local
    retrieve_certificate
  end

  def submit_csr
    debug "generating new key for #{@resource[:name]} and submitting csr"
    ensure_cadir if @resource[:ca_location] == :local
    Puppet::SSL::Oids.register_puppet_oids if Puppet::SSL::Oids.respond_to?('register_puppet_oids')

    if at_least_puppet6
      key = OpenSSL::PKey::RSA.new(Puppet[:keylength].to_i)
      @cert_provider.save_private_key(@resource[:name], key)

      csr = create_request(key)
      ssl_context = @machine.ensure_ca_certificates
      route = create_route(ssl_context)
      begin
        route.put_certificate_request(@resource[:name], csr, ssl_context: ssl_context)
      rescue Puppet::HTTP::ResponseError => e
        if e.response.code == 400
          raise Puppet::Error.new(_("Could not submit certificate request for '%{name}' to %{url} due to a conflict on the server") % { name: @resource[:name], url: route.url }, e)
        end

        raise Puppet::Error.new(_('Failed to submit certificate request: %{message}') % { message: e.message  }, e)
      rescue StandardError => e
        raise Puppet::Error.new(_('Failed to submit certificate request: %{message}') % { message: e.message  }, e)
      end
      @cert_provider.save_request(@resource[:name], csr)
      Puppet.notice(_("Submitted certificate request for '%{name}' to %{url}") % { name: @resource[:name], url: route.url })
    else
      host = Puppet::SSL::Host.new(@resource[:name])
      if @resource[:dns_alt_names]
        host.generate_certificate_request(:dns_alt_names => @resource[:dns_alt_names].join(','))
      else
        host.generate_certificate_request
      end
    end
  end

  def create_request(key)
    options = {}
    # csr_attributes could maybe become part of the type instead??
    csr_attributes = Puppet::SSL::CertificateRequestAttributes.new(Puppet[:csr_attributes])

    if csr_attributes.load
      options[:csr_attributes] = csr_attributes.custom_attributes
      options[:extension_requests] = csr_attributes.extension_requests
    end

    options[:dns_alt_names] = @resource[:dns_alt_names].join(',') if @resource[:dns_alt_names]

    csr = Puppet::SSL::CertificateRequest.new((@resource[:name]))
    csr.generate(key, options)
  end

  def retrieve_certificate
    timeout = 0
    certname = @resource[:name]
    debug "retrieving certificate for #{certname}"
    timeout = @resource[:waitforcert].to_i if @resource[:waitforcert]

    if at_least_puppet6
      ssl_context = @machine.ensure_ca_certificates
      cert = download_cert(ssl_context)
    else
      cert = certificate # No really, the indirection stuff we use also tries to download the cert from the CA
    end

    if cert.nil? && timeout != 0
      notice(<<-EOL.gsub(/\s+/, " ").strip)
        Waiting #{timeout} seconds for #{certname} to be signed. Please
        sign this certificate on the CA host or use the Request Manager
        in the Puppet Enterprise Console.
      EOL

      while timeout > 0 && cert.nil?
        cert = if at_least_puppet6
                 download_cert(ssl_context)
               else
                 certificate
               end
        sleep 2 # trying every second might be a bit too rapid?
        timeout -= 1
      end
    end

    # If a cert didn't result then fail verbosely
    unless cert
      raise Puppet::Error, "Unable to retrieve certificate for #{@resource[:name]}. You may need to sign this certificate on the CA host by running `puppetserver ca sign --cert #{@resource[:name]}`"
    end

    if at_least_puppet6
      @cert_provider.save_client_cert(@resource[:name], cert)
      @cert_provider.delete_request(@resource[:name])
    else
      delete_file(File.join(Puppet[:requestdir], "#{@resource[:name].downcase}.pem"))
    end
  end

  def download_cert(ssl_context)
    route = create_route(ssl_context)
    Puppet.info _("Downloading certificate '%{name}' from %{url}") % { name: @resource[:name], url: route.url }
    _, x509 = route.get_certificate(@resource[:name], ssl_context: ssl_context)
    cert = OpenSSL::X509::Certificate.new(x509)
    Puppet.notice _("Downloaded certificate '%{name}' with fingerprint %{fingerprint}") % { name: @resource[:name], fingerprint: fingerprint(cert) }
    cert
  rescue Puppet::HTTP::ResponseError => e
    unless e.response.code == 404
      raise Puppet::Error.new(_('Failed to download certificate: %{message}') % { message: e.message }, e)
    end
  rescue StandardError => e
    raise Puppet::Error.new(_('Failed to download certificate: %{message}') % { message: e.message }, e)
  end

  def sign_certificate
    debug "signing certificate for #{@resource[:name]}"

    req = Net::HTTP::Put.new("/puppet-ca/v1/certificate_status/#{@resource[:name]}", { 'Content-Type' => 'application/json' })
    req.body = JSON.dump({ desired_state: 'signed' })
    https = Net::HTTP.new(Puppet.settings[:ca_server], Puppet.settings[:ca_port])
    https.use_ssl = true
    https.cert = OpenSSL::X509::Certificate.new(File.read(Puppet.settings[:hostcert]))
    https.key = OpenSSL::PKey::RSA.new(File.read(Puppet.settings[:hostprivkey]))
    https.verify_mode = OpenSSL::SSL::VERIFY_PEER
    https.ca_file = Puppet.settings[:localcacert]
    resp = https.start { |cx| cx.request(req) }
    warning "failed to sign certificate: #{resp.body}" if resp.code_type != Net::HTTPNoContent
  end

  def ensure_cadir
    # This makes everything "just work" even on systems without a cadir yet
    cadir = Puppet.settings[:cadir]
    return if File.exists?(cadir)

    FileUtils.mkdir_p(File.join(cadir, 'requests'), :mode => 0750)
    FileUtils.chown_R(Puppet.settings[:user], Puppet.settings[:group], cadir)
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
    warning "failed to clean certificate: #{resp.body}" if resp.code_type != Net::HTTPNoContent
  end

  def destroy
    clean if @resource[:clean] == :true

    filename = "#{@resource[:name].downcase}.pem"

    delete_file(File.join(Puppet[:privatekeydir], filename))
    @key = nil
    delete_file(File.join(Puppet[:certdir], filename))
    @certificate = nil
    delete_file(File.join(Puppet[:requestdir], filename), false)
  end

  def delete_file(path, warn = true)
    debug("deleting #{path}")
    Puppet::FileSystem.unlink(path)
  rescue Errno::ENOENT
    warning("file not found when trying to delete #{path}") if warn
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

  def key
    if at_least_puppet6
      debug("Attempting to load key for #{@resource[:name]}")
      @key ||= @cert_provider.load_private_key(@resource[:name])
    else
      @key ||= Puppet::SSL::Key.indirection.find(@resource[:name])
    end
  end

  def certificate
    if at_least_puppet6
      debug("Attempting to load cert for #{@resource[:name]}") unless @certificate
      @certificate ||= @cert_provider.load_client_cert(@resource[:name])
    else
      if (cert = Puppet::SSL::Certificate.indirection.find(@resource[:name]))
        @certificate ||= cert.content
      end
    end
  end

  def is_valid?
    return if certificate.nil?

    grace_time = @resource[:renewal_grace_period] * 60 * 60 * 24
    certificate.not_after - grace_time > Time.now
  end

  def debug(msg)
    Puppet.debug "puppet_certificate: #{msg}"
  end

  def warning(msg)
    Puppet.warning "puppet_certificate: #{msg}"
  end

  def fingerprint(cert)
    Puppet::SSL::Digest.new(nil, cert.to_der)
  end

  def create_route(ssl_context)
    Puppet.runtime[:http].create_session.route_to(:ca, ssl_context: ssl_context)
  end

  def at_least_puppet6
    version = Gem::Version.new(Puppet.version)

    # The replacement APIs were only introduced in Puppet 6.4
    if version >= Gem::Version.new('6.0.0') && version < Gem::Version.new('6.4.0')
      raise Puppet::Error, "#{Puppet.version} is not supported by the `puppet_certificate` type."
    end

    version >= Gem::Version.new('6.4.0')
  end
end
