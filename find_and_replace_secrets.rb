#!/usr/bin/env ruby
##########################################################################################
# This Script was written to fetch Secrets from Vault during the build of CloudForms /
# ManageIQ Statemachine Code. We're searching for Attributes in the Statemachine with
# Name: VAULT_INFO and Value: VAULT://secret/.... 
##########################################################################################

##################
# external gems
require 'ezcrypto'
require 'base64'
require 'yaml'
require 'openssl'
require 'json'
require 'rest-client'

##################
# some variables
$VERBOSE       = nil                                    # Disable any warnings in script output
@@DEBUG        = true                                   # debug flag
action         = nil                                    # helper variable
value          = nil                                    # helper variable
@@keyName      = "./data/v2_key"                        # Name of the secret key
@@dataDir      = "./data/data/StatemachineDomainFolder" # Data Directory for statemachine
@@vaultAddress = "vault.fqdn.local."

# determine VAULT_TOKEN from ENV or UserHome
if ENV['VAULT_TOKEN']
  @@vaultToken = ENV['VAULT_TOKEN']
elsif File.exists?("#{ENV['HOME']}/.vault-token")
  @@vaultToken = IO.read("#{ENV['HOME']}/.vault-token")
else
  raise "could not find any VAULT_TOKEN"
end

##################
# Vault Connector Class
class Vault
  def get_credential(path)
    options = { api_method: 'get', url: "https://#{@@vaultAddress}", service_url: "/v1/#{path}" }
    vault_call(options)
  end

  private

  def vault_call(options)
    begin
      resource_config = {
        :url        => options[:url] + options[:service_url],
        :method     => :GET,
        :verify_ssl => OpenSSL::SSL::VERIFY_NONE,
        :headers    => {
          'X-Vault-Token' => @@vaultToken
        }
      }
      log("debug", "Vault-Call Inspection: #{resource_config}") if @@DEBUG
      request = RestClient::Request.new( resource_config )
      JSON.parse(request.execute)
    rescue => e
      log("error", "Vault-Call: #{e} - #{e.backtrace.join("\n")}")
    end
  end
end

##################
# Crypto Helper Class
class CryptString
  def initialize(_str = nil, enc_alg = nil, key = nil, iv = nil)
    @enc_alg = enc_alg
    @key     = key
    @iv      = iv
  end

  def encrypt64(str)
    cip = OpenSSL::Cipher::Cipher.new(@enc_alg)
    cip.encrypt
    cip.key = @key
    cip.iv  = @iv
    es = cip.update(str)
    es << cip.final
    [es].pack('m')
  end
  alias_method :encrypt, :encrypt64

  def decrypt64(str)
    cip = OpenSSL::Cipher::Cipher.new(@enc_alg)
    cip.decrypt
    cip.key = @key
    cip.iv  = @iv
    rs = cip.update(str.unpack('m').join)
    rs << cip.final
    rs
  end
  alias_method :decrypt, :decrypt64
end

##################
# CF / MIQ Password Helper Class
class MiqPassword
  REGEXP = /v([0-9]+):\{([^}]*)\}/
  REGEXP_START_LINE = /^#{REGEXP}/

  def initialize
    @key = self.class.load_v2_key
  end

  def encrypt(str, ver = "v2", key = @key)
    value = key.encrypt64(str).delete("\n") unless str.nil? || str.empty?
    "#{ver}:{#{value}}"
  end

  def decrypt(str, legacy = false)
    if str.nil? || str.empty?
      str
    else
      ver, enc = self.class.split(str)
      return "" if enc.empty?
      ver ||= "0"
      key_name = (ver == "2" && legacy) ? "alt" : "v#{ver}"
      begin
        self.class.keys[key_name].decrypt64(enc).force_encoding('UTF-8')
      rescue
        raise "can not decrypt v#{ver}_key encrypted string"
      end
    end
  end

  def self.split(encrypted_str)
    if encrypted_str.nil? || encrypted_str.empty?
      [nil, encrypted_str]
    else
      if encrypted_str =~ REGEXP_START_LINE
        [$1, $2]
      else
        raise "key does not match the exspected format"
      end
    end
  end

  def self.encrypt(str)
    new.encrypt(str) if str
  end

  def self.decrypt(str)
    new.decrypt(str)
  end

  def self.keys
    @all_keys ||= {"v2" => load_v2_key}.delete_if { |_n, v| v.nil? }
  end

  def self.load_v2_key
    begin
      ez_load(@@keyName)
    rescue => e
      key_file = File.expand_path(@@keyName, ".")
      raise "#{key_file} doesn't exist!"
    end
  end

  protected

  def self.ez_load(filename, recent = true)
    return filename if filename.respond_to?(:decrypt64)
    filename = File.expand_path(filename, ".") unless File.exist?(filename)
    if !File.exist?(filename)
      raise "could not find key-file"
    elsif recent
      EzCrypto::Key.load(filename)
    else
      params = YAML.load_file(filename)
      CryptString.new(nil, params[:algorithm], params[:key], params[:iv])
    end
  end
end

##################
# log helper method
def log(severity, message)
  print "#{Time.now} [#{severity.upcase}] => #{message}\n"
end

##################
# grep helper method
def get_filenames_where_vault_is_defined
  found_entries = Array.new
  %x[ grep -Hir -e 'VAULT://' #{@@dataDir} ].split("\n").each{|line| found_entries << line.split(":")[0] }
  found_entries.empty? ? nil : found_entries
end

##################
# logic
files = get_filenames_where_vault_is_defined

if files.nil?
  log("info", "Found no Attributes with 'VAULT://' String in Statemachine Attributes")
  exit 0
else
  log("info", "Found Files with Attributes 'VAULT://': <#{files.inspect}>")
end

files.each do |yamlMethodeFileName|
  enigma = MiqPassword.new

  # generate instance file name and log them
  log("info", "process file #{yamlMethodeFileName}")
  yamlInstanceFileName = yamlMethodeFileName[/(.*\/)\w+\.yaml/, 1] + "__class__.yaml"
  log("info", "instance definition file should be #{yamlInstanceFileName}")

  # load files
  begin 
    yamlMethodFileContent = YAML.load_file(yamlMethodeFileName)
    log("info", "loaded #{yamlMethodeFileName}")
  rescue => e
    log("error", "failed to load #{yamlMethodeFileName}")
  end
  begin
    yamlInstanceFileContent = YAML.load_file(yamlInstanceFileName)
    log("info", "loaded #{yamlInstanceFileName}")
  rescue => e
    log("error", "failed to load #{yamlInstanceFileName}")
  end

  # find which attributes are needed from InstanceYAMLContent
  matched_fields    = yamlInstanceFileContent["object"]["schema"].select{|sh| sh["field"]["aetype"] =~ /^attribute$/i and not sh["field"]["name"] =~ /^VAULT_INFO$/i }
  needed_fields     = matched_fields.map{|map| map["field"]["name"] }
  begin 
    matched_vaultinfo = yamlMethodFileContent["object"]["fields"].select{|field| field.has_key?("VAULT_INFO") }
  rescue => e
    log("error", "failed to find VAULT_INFO Field, could it be possible that you defined the VAULT_INFO Field in the Instance Shema and not in the Method Schema ?")
  end
  
  raise "no attributes defined in #{yamlInstanceFileName}, but VAULT-Secret-Address found, this is weired" if needed_fields.count < 1
  raise "no VAULT-Secret-Address found in file #{yamlMethodeFileName}" if matched_vaultinfo.count < 1

  # split informations and request vault for needed informations 
  vault_path        = matched_vaultinfo[0]["VAULT_INFO"]["value"].split("://")[1]
  log("info", "Instance has defined #{needed_fields.count} Attributes: #{needed_fields}")
  log("info", "Found Vault-Secret-Path: #{vault_path}")
  log("debug", "Initializing Vault Object") if @@DEBUG
  vaultObject = Vault.new
  vaultRawResponse = vaultObject.get_credential(vault_path)
  vaultResponse = vaultRawResponse["data"]
  log("debug", "Got answer from Vault: <#{vaultResponse}>") if @@DEBUG

  # validate all needed_fields are available in Vault-Store
  needed_fields.each do |nf|
    # skip parameters which are UPPERCASE , they're optional !
    ( log("info", "skip Parameter: <#{nf}> - it is UPPERCASE, this means OPTIONAL"); next ) if nf.match(/\p{Lower}/).nil?
    raise "could not find information for: <#{nf}> in Vault-Secret-Store" unless vaultResponse.has_key?(nf)
  end
  log("info", "found every attribute in Vault Store")

  # build new YAML
  newHash = Marshal.load(Marshal.dump(yamlMethodFileContent)) # deep clone the Hash
  newHash["object"]["fields"].reverse!
  needed_fields.each do |nf|
    next if nf.match(/\p{Lower}/).nil?
    if newHash["object"]["fields"].select{|s| s.has_key?(nf)}.count == 1
      log("info", "Parameter <#{nf}> is already defined in statemachine")
      if nf =~ /password/i 
        log("info", "found password - enigma is running hot to encrypt the secret and replace value")
        foundHash = newHash["object"]["fields"].find{|f| f.has_key?(nf) }
        foundHash[nf]["value"] = enigma.encrypt(vaultResponse[nf])
      else
        log("info", "replace <#{nf}> in store")
        foundHash = newHash["object"]["fields"].find{|f| f.has_key?(nf) }
        foundHash[nf]["value"] = vaultResponse[nf]
      end
    else
      log("info", "Parameter <#{nf}> is not defined, create value")
      if nf =~ /password/i 
        log("info", "found password - enigma is running hot to encrypt the secret")
        newHash["object"]["fields"] << { nf => { "value" => enigma.encrypt(vaultResponse[nf]) } }
      else
        log("info", "append <#{nf}> to store")
        newHash["object"]["fields"] << { nf => { "value" => vaultResponse[nf] } }
      end
    end
  end
  newHash["object"]["fields"].reverse!

  print "---------OLD FILE---------\n#{yamlMethodFileContent.to_yaml}\n"
  print "---------NEW FILE---------\n#{newHash.to_yaml}\n"

  log("info", "write new YAML file to: #{yamlMethodeFileName}")
  newYAML = File.open(yamlMethodeFileName, "w") 
  newYAML.puts newHash.to_yaml
  newYAML.close

  log("info", "Logic finished for file: #{yamlMethodeFileName}")
end
