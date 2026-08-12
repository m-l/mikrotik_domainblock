#!/usr/bin/env ruby
# frozen_string_literal: true

# domainblock.rb
#
# Reads new inbound source IPs queued by the router into the "domainblock-check"
# address-list, does a reverse-DNS (PTR) lookup on each, matches the hostname
# against patterns in domainblock-patterns.txt, and writes matches into the
# "domainblock-banned" address-list on the router via the RouterOS API.
#
# The router does the actual dropping (see the firewall rules in README).
# This script only decides *which* IPs belong in the banned list.
#
# NO external gems required — uses only Ruby stdlib. Config and patterns are
# read from the same directory as this script (override with env vars).

require "socket"
require "resolv"
require "yaml"
require "logger"
require "ipaddr"
require "set"
require "openssl"
require "timeout"

# ============================================================================
# Minimal RouterOS API client (pure stdlib)
# The RouterOS API is a stream of "sentences"; each sentence is a list of
# "words"; each word is length-prefixed. See help.mikrotik.com API docs.
# ============================================================================
class RouterOS
  class Error < StandardError; end

  def initialize(host:, user:, pass:, port: 8728, tls: false)
    raw = TCPSocket.new(host, port)
    raw.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
    if tls
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE   # LAN, self-signed router cert
      @sock = OpenSSL::SSL::SSLSocket.new(raw, ctx)
      @sock.sync_close = true
      @sock.connect
    else
      @sock = raw
    end
    login(user, pass)
  end

  # ---- length encoding (RouterOS variable-length prefix) ---------------------
  def encode_length(len)
    if len < 0x80
      [len].pack("C")
    elsif len < 0x4000
      [(len | 0x8000)].pack("n")
    elsif len < 0x200000
      [(len >> 16) | 0xC0, (len >> 8) & 0xFF, len & 0xFF].pack("C3")
    elsif len < 0x10000000
      [(len >> 24) | 0xE0, (len >> 16) & 0xFF, (len >> 8) & 0xFF, len & 0xFF].pack("C4")
    else
      [0xF0, (len >> 24) & 0xFF, (len >> 16) & 0xFF, (len >> 8) & 0xFF, len & 0xFF].pack("C5")
    end
  end

  def write_word(word)
    b = word.b
    @sock.write(encode_length(b.bytesize))
    @sock.write(b)
  end

  def write_sentence(words)
    words.each { |w| write_word(w) }
    write_word("") # empty word terminates the sentence
  end

  def read_length
    b0 = @sock.read(1).unpack1("C")
    if (b0 & 0x80) == 0x00
      b0
    elsif (b0 & 0xC0) == 0x80
      ((b0 & 0x3F) << 8) | @sock.read(1).unpack1("C")
    elsif (b0 & 0xE0) == 0xC0
      rest = @sock.read(2).unpack("C2")
      ((b0 & 0x1F) << 16) | (rest[0] << 8) | rest[1]
    elsif (b0 & 0xF0) == 0xE0
      rest = @sock.read(3).unpack("C3")
      ((b0 & 0x0F) << 24) | (rest[0] << 16) | (rest[1] << 8) | rest[2]
    else
      rest = @sock.read(4).unpack("C4")
      (rest[0] << 24) | (rest[1] << 16) | (rest[2] << 8) | rest[3]
    end
  end

  def read_word
    len = read_length
    return "" if len.zero?
    @sock.read(len)
  end

  def read_sentence
    words = []
    loop do
      w = read_word
      break if w == ""
      words << w
    end
    words
  end

  # Send a command (array of words), collect reply sentences until !done.
  # Returns array of hashes (one per !re). Raises on !trap/!fatal.
  def talk(words)
    write_sentence(words)
    results = []
    loop do
      sentence = read_sentence
      break if sentence.empty?
      reply = sentence.shift
      attrs = {}
      sentence.each do |w|
        if w.start_with?("=")
          k, v = w[1..].split("=", 2)
          attrs[k] = v
        end
      end
      case reply
      when "!re"   then results << attrs
      when "!done" then break
      when "!trap", "!fatal"
        raise Error, (attrs["message"] || sentence.join(" "))
      end
    end
    results
  end

  def login(user, pass)
    talk(["/login", "=name=#{user}", "=password=#{pass}"])
  rescue Error => e
    raise Error, "login failed: #{e.message}"
  end

  def close
    begin
      talk(["/quit"])
    rescue StandardError
      nil
    end
    @sock.close rescue nil
  end
end

# ============================================================================
# WatchedPorts — keep the FORWARD/DSTNAT queue rule's dst-port list in sync
# with the ports you INTENTIONALLY forward, discovered by a "#domainblock" tag
# in the comment of your static NAT (dst-nat) rules.
#
#   - Tag NAT dstnat rules you want PTR-watched with "#domainblock".
#   - This unions their to-ports (fallback dst-port) and writes that set onto
#     the forward queue FILTER rule (chain=forward, add-src-to-address-list,
#     also tagged "#domainblock").
#   - Dynamic UPnP/NAT-PMP mappings (e.g. torrent 16881) are skipped.
#   - Disabled NAT rules are skipped.
#   - Writes ONLY the forward queue rule; the input queue rule is never touched.
# ============================================================================
module WatchedPorts
  TAG = "#domainblock"

  def self.split_ports(spec)
    return [] if spec.nil? || spec.to_s.strip.empty?
    spec.to_s.split(",").map(&:strip).reject(&:empty?)
  end

  def self.tagged?(comment) = comment.to_s.include?(TAG)
  def self.truthy?(v)       = %w[true yes].include?(v.to_s.strip.downcase)
  def self.nonempty(v)      = (v.nil? || v.to_s.strip.empty?) ? nil : v.to_s.strip
  def self.numeric_key(p)   = (p =~ /\A\d+\z/ ? [0, p.to_i] : [1, p])

  # Union of watched ports from tagged, enabled, static dst-nat rules.
  # Port taken from to-ports (what the forward chain sees post-NAT), falling
  # back to dst-port when the port is not translated.
  def self.derive(nat_rules, exclude_ports: [])
    excl = exclude_ports.map { |p| p.to_s.strip }
    ports = []
    nat_rules.each do |r|
      next unless r["chain"]  == "dstnat"
      next unless r["action"] == "dst-nat"
      next if truthy?(r["disabled"])
      next if truthy?(r["dynamic"])
      next unless tagged?(r["comment"])
      src = nonempty(r["to-ports"]) || nonempty(r["dst-port"])
      next if src.nil?
      ports.concat(split_ports(src))
    end
    ports.uniq.reject { |p| excl.include?(p) }.sort_by { |p| numeric_key(p) }
  end

  def self.forward_queue_rule(filter_rules)
    filter_rules.find do |r|
      r["chain"] == "forward" &&
        r["action"] == "add-src-to-address-list" &&
        tagged?(r["comment"])
    end
  end

  def self.same_set?(current_spec, desired_ports)
    split_ports(current_spec).sort == desired_ports.sort
  end

  # Call once per run, after the ban pass, reusing the connected api.
  def self.reconcile(api, exclude_ports: [], logger: nil, dry_run: false)
    nat    = api.talk(["/ip/firewall/nat/print"])
    desired = derive(nat, exclude_ports: exclude_ports)

    if desired.empty?
      logger&.info "watched-ports: no tagged NAT rules resolved to a port; " \
                   "leaving forward queue rule unchanged (refusing to widen/empty it)"
      return
    end

    filters = api.talk(["/ip/firewall/filter/print"])
    rule = forward_queue_rule(filters)
    if rule.nil?
      logger&.info "watched-ports: forward queue rule not found " \
                   "(chain=forward, add-src-to-address-list, tag #{TAG.inspect})"
      return
    end

    current = rule["dst-port"].to_s
    if same_set?(current, desired)
      logger&.debug "watched-ports: no change (#{desired.join(',')})"
      return
    end

    desired_spec = desired.join(",")
    logger&.info "watched-ports: #{current.empty? ? '(all dstnat)' : current} -> #{desired_spec}"
    return if dry_run

    api.talk(["/ip/firewall/filter/set",
              "=.id=#{rule['.id']}",
              "=dst-port=#{desired_spec}"])
    logger&.info "watched-ports: forward queue rule updated"
  end
end

# ============================================================================
# Paths — config & patterns live in the SAME directory as this script,
# unless overridden by env vars.
# ============================================================================
SCRIPT_DIR    = File.dirname(File.realpath(__FILE__))
CONFIG_PATH   = ENV.fetch("DOMAINBLOCK_CONFIG",   File.join(SCRIPT_DIR, "config.yml"))
PATTERNS_PATH = ENV.fetch("DOMAINBLOCK_PATTERNS", File.join(SCRIPT_DIR, "domainblock-patterns.txt"))

config = YAML.safe_load(File.read(CONFIG_PATH))

ROUTER_HOST = config.fetch("router_host")
ROUTER_PORT = config.fetch("router_port", 8728).to_i
ROUTER_USER = config.fetch("router_user", "domainblock")
ROUTER_PASS = config.fetch("router_pass")
ROUTER_TLS  = config.fetch("router_tls", false)

CHECK_LIST  = config.fetch("check_list",  "domainblock-check")
BANNED_LIST = config.fetch("banned_list", "domainblock-banned")
BAN_TIMEOUT = config.fetch("ban_timeout", "7d")
DNS_TIMEOUT = config.fetch("dns_timeout", 3).to_i

# Watched-ports auto-management (forward/DSTNAT queue rule dst-port sync).
# Enabled by default; set `watched_ports_manage: false` in config to turn off.
WATCHED_MANAGE  = config.fetch("watched_ports_manage", true)
WATCHED_EXCLUDE = config.fetch("exclude_ports", [])
WATCHED_DRYRUN  = (ENV["DOMAINBLOCK_DRYRUN"] == "1")

logger = Logger.new($stdout)
logger.level = (ENV["DOMAINBLOCK_DEBUG"] == "1") ? Logger::DEBUG : Logger::INFO
logger.formatter = proc { |sev, time, _p, msg| "#{time.strftime('%Y-%m-%d %H:%M:%S')} #{sev} #{msg}\n" }

# ============================================================================
# Patterns
# ============================================================================
def load_patterns(path, logger)
  unless File.exist?(path)
    logger.warn "Patterns file #{path} not found; nothing will be banned."
    return []
  end
  File.readlines(path).filter_map do |line|
    line = line.strip
    next if line.empty? || line.start_with?("#")
    line.downcase
  end
end

# Convert a glob like *.googleusercontent.com into an anchored Regexp.
# '*' matches one or more DNS labels.
def glob_to_regexp(glob)
  escaped = Regexp.escape(glob).gsub('\*', '[^.]+(?:\.[^.]+)*')
  /\A#{escaped}\z/i
end

def hostname_matches?(hostname, patterns)
  h = hostname.downcase.sub(/\.\z/, "")
  patterns.any? { |p| glob_to_regexp(p).match?(h) }
end

# ============================================================================
# Reverse DNS
# ============================================================================
def reverse_lookup(ip, timeout)
  Resolv::DNS.open do |dns|
    dns.timeouts = timeout
    dns.getnames(ip).map(&:to_s)
  end
rescue Resolv::ResolvError, IOError, SystemCallError, Timeout::Error
  []
end

# ============================================================================
# Main
# ============================================================================
patterns = load_patterns(PATTERNS_PATH, logger)
logger.info "Loaded #{patterns.size} pattern(s) from #{PATTERNS_PATH}"
exit 0 if patterns.empty?

begin
  api = RouterOS.new(host: ROUTER_HOST, port: ROUTER_PORT, user: ROUTER_USER,
                     pass: ROUTER_PASS, tls: ROUTER_TLS)
rescue StandardError => e
  logger.error "Cannot connect to RouterOS #{ROUTER_HOST}:#{ROUTER_PORT} -> #{e.class}: #{e.message}"
  exit 1
end

begin
  check = api.talk(["/ip/firewall/address-list/print",
                    "?list=#{CHECK_LIST}", "=.proplist=address"])
  banned = api.talk(["/ip/firewall/address-list/print",
                     "?list=#{BANNED_LIST}", "=.proplist=address"])

  already = Set.new(banned.map { |e| e["address"] })
  candidates = check.map { |e| e["address"] }.compact.uniq.reject { |ip| already.include?(ip) }

  logger.info "Queue #{CHECK_LIST}: #{check.size} entr(y/ies), #{candidates.size} new IP(s) to check"

  banned_now = 0
  candidates.each do |ip|
    begin
      IPAddr.new(ip)
    rescue IPAddr::Error
      next
    end

    names = reverse_lookup(ip, DNS_TIMEOUT)
    if names.empty?
      logger.debug "#{ip} -> (no PTR)"
      next
    end

    match = names.find { |n| hostname_matches?(n, patterns) }
    unless match
      logger.debug "#{ip} -> #{names.join(', ')} (no match)"
      next
    end

    comment = "domainblock: #{match} @#{Time.now.strftime('%Y-%m-%dT%H:%M:%S')}"
    begin
      api.talk(["/ip/firewall/address-list/add",
                "=list=#{BANNED_LIST}", "=address=#{ip}",
                "=timeout=#{BAN_TIMEOUT}", "=comment=#{comment}"])
      banned_now += 1
      logger.info "BANNED #{ip} (PTR #{match})"
    rescue RouterOS::Error => e
      if e.message.include?("already have")
        logger.debug "#{ip} already banned"
      else
        logger.warn "Failed to ban #{ip}: #{e.message}"
      end
    end
  end

  logger.info "Run complete: #{banned_now} new ban(s)"

  # Keep the forward/DSTNAT queue rule's dst-port list in sync with tagged NAT.
  if WATCHED_MANAGE
    begin
      WatchedPorts.reconcile(api,
                             exclude_ports: WATCHED_EXCLUDE,
                             logger: logger,
                             dry_run: WATCHED_DRYRUN)
    rescue RouterOS::Error => e
      logger.warn "watched-ports: reconcile failed: #{e.message}"
    end
  end
ensure
  api.close
end
