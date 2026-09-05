#!/usr/bin/env ruby
# frozen_string_literal: true

# domainblock-monthly-report.rb
#
# Once a month: finds the most recently rotated seen.csv archive (produced by
# logrotate — see the logrotate.d/domainblock drop-in), tallies no-match PTR
# suffixes and no-ptr ASN names, diffs them against the CURRENT
# domainblock-patterns.txt / domainblock-asn-patterns.txt, and emails you only
# the ones that AREN'T already covered — ranked by hit volume.
#
# It also reads across every archive logrotate is currently keeping (up to 6
# months) to look for a different signal: sources that show up on many
# separate DAYS with low volume each time — an attacker pacing attempts to
# avoid ever ranking near the top of a by-volume list. That section is
# labeled "Persistent" below and reports distinct-day count as the primary
# ranking, not hits.
#
# This is a MECHANICAL coverage report, not a verdict. It can tell you "this
# suffix/ASN isn't in your pattern files and had N hits this month" or "showed
# up on N separate days" — it can't tell you whether something is a benign
# self-identifying scanner, a bulletproof host, or a residential ISP you
# should leave alone. That still takes an actual look (a search, a human
# decision) before you add anything it lists to your pattern files.
#
# NO external gems — stdlib only (Net::SMTP, Resolv, YAML, Zlib), same
# philosophy as domainblock.rb. The small pattern-matching / ASN-lookup
# functions below are intentionally duplicated from domainblock.rb rather
# than shared, so this script stays standalone and never risks breaking the
# main ban loop.

require "yaml"
require "resolv"
require "timeout"
require "net/smtp"
require "logger"
require "set"

# ============================================================================
# Paths & config
# ============================================================================
SCRIPT_DIR        = File.dirname(File.realpath(__FILE__))
CONFIG_PATH       = ENV.fetch("DOMAINBLOCK_CONFIG",   File.join(SCRIPT_DIR, "config.yml"))
PATTERNS_PATH     = ENV.fetch("DOMAINBLOCK_PATTERNS", File.join(SCRIPT_DIR, "domainblock-patterns.txt"))
ASN_PATTERNS_PATH = ENV.fetch("DOMAINBLOCK_ASN_PATTERNS", File.join(SCRIPT_DIR, "domainblock-asn-patterns.txt"))

config = YAML.safe_load(File.read(CONFIG_PATH))

REPORT_ON        = config.fetch("monthly_report", false)
SEEN_LOG_FILE     = File.expand_path(config.fetch("seen_log_file", "seen.csv"), SCRIPT_DIR)
REPORT_TOP_N      = config.fetch("report_top_n", 20).to_i
REPORT_MIN_DAYS   = config.fetch("report_persistent_min_days", 3).to_i
ASN_CHECK_ENABLED = config.fetch("asn_check", false)
DNS_TIMEOUT       = config.fetch("dns_timeout", 3).to_i

SMTP_HOST     = config.fetch("report_smtp_host", nil)
SMTP_PORT     = config.fetch("report_smtp_port", 587).to_i
SMTP_USER     = config.fetch("report_smtp_user", nil)
SMTP_PASS     = config.fetch("report_smtp_pass", nil)
SMTP_STARTTLS = config.fetch("report_smtp_starttls", true)
REPORT_FROM   = config.fetch("report_from", nil)
REPORT_TO     = config.fetch("report_to", nil)
REPORT_SUBJECT_TEMPLATE = config.fetch("report_subject", "domainblock monthly report - %{month}")

DRY_RUN = (ENV["DOMAINBLOCK_DRYRUN"] == "1")

logger = Logger.new($stdout)
logger.level = (ENV["DOMAINBLOCK_DEBUG"] == "1") ? Logger::DEBUG : Logger::INFO
logger.formatter = proc { |sev, time, _p, msg| "#{time.strftime('%Y-%m-%d %H:%M:%S')} #{sev} #{msg}\n" }

unless REPORT_ON
  logger.info "monthly_report is false in config.yml — nothing to do"
  exit 0
end

# ============================================================================
# Find all rotated archives — never the live current-month seen.csv. Matches
# logrotate's `dateext` / `dateformat -%Y-%m` naming: seen.csv-YYYY-MM or
# seen.csv-YYYY-MM.gz once `compress` has run. Returned oldest-first; the
# last element is "last month" (the primary archive for the volume sections
# below). Reading all of them, not just the latest, is what lets the
# persistence section below see an attacker who paces attempts across
# multiple months, not just within one.
# ============================================================================
def find_all_archives(seen_log_path, logger)
  dir  = File.dirname(seen_log_path)
  base = File.basename(seen_log_path)
  candidates = Dir.glob(File.join(dir, "#{base}-????-??")) +
               Dir.glob(File.join(dir, "#{base}-????-??.gz"))
  if candidates.empty?
    logger.warn "No rotated archive found matching #{base}-YYYY-MM[.gz] in #{dir}. " \
                "Has logrotate run yet this cycle?"
    return []
  end
  candidates.sort_by { |f| f[/(\d{4}-\d{2})(?:\.gz)?\z/, 1] }
end

def read_archive(path)
  if path.end_with?(".gz")
    require "zlib"
    Zlib::GzipReader.open(path) { |gz| gz.read }
  else
    File.read(path)
  end
end

def parse_archive(path)
  read_archive(path).each_line.filter_map do |line|
    parts = line.chomp.split(",", 5)
    next if parts.size < 4
    { date: parts[0].to_s[0, 10], ip: parts[1], ptr: parts[2], verdict: parts[3], detail: parts[4].to_s }
  end
end

# ============================================================================
# Patterns (duplicated from domainblock.rb — see file header)
# ============================================================================
def load_patterns(path, logger, label: "Patterns")
  unless File.exist?(path)
    logger.warn "#{label} file #{path} not found; treating as empty."
    return []
  end
  File.readlines(path).filter_map do |line|
    line = line.strip
    next if line.empty? || line.start_with?("#")
    line.downcase
  end
end

def glob_to_regexp(glob)
  escaped = Regexp.escape(glob).gsub('\*', '[^.]+(?:\.[^.]+)*')
  /\A#{escaped}\z/i
end

def hostname_matches?(hostname, patterns)
  h = hostname.downcase.sub(/\.\z/, "")
  patterns.any? { |p| glob_to_regexp(p).match?(h) }
end

def asn_name_matches?(asn_name, patterns)
  return false if asn_name.nil?
  patterns.any? { |p| File.fnmatch(p, asn_name, File::FNM_CASEFOLD) }
end

# Turn "AS41608 NextGenWebs-NL - NextGenWebs, S.L., ES" into "*NextGenWebs-NL*"
# — the handle before the first " - ", wrapped for domainblock-asn-patterns.txt.
# Falls back to the whole name (minus the AS<num> prefix) if there's no dash.
def asn_pattern_from_label(label)
  name = label.sub(/\AAS\d+\s+/, "")
  handle = name.split(" - ", 2).first || name
  "*#{handle.strip}*"
end

# ============================================================================
# ASN lookup (Team Cymru whois-over-DNS), parallelized with threads — this
# script may resolve thousands of unique no-ptr IPs once a month, unlike
# domainblock.rb's own reactive one-at-a-time lookup.
# ============================================================================
def txt_lookup(name, timeout)
  Resolv::DNS.open do |dns|
    dns.timeouts = timeout
    dns.getresources(name, Resolv::DNS::Resource::IN::TXT).map { |r| r.strings.join }
  end
rescue Resolv::ResolvError, IOError, SystemCallError, Timeout::Error
  []
end

def asn_lookup(ip, timeout)
  octets = ip.split(".").reverse.join(".")
  origin = txt_lookup("#{octets}.origin.asn.cymru.com", timeout).first
  return nil unless origin
  asn = origin.split("|").first.to_s.strip.split(" ").first
  return nil if asn.nil? || asn.empty?
  name_rec = txt_lookup("AS#{asn}.asn.cymru.com", timeout).first
  return nil unless name_rec
  fields = name_rec.split("|").map(&:strip)
  { asn: asn, name: fields[4] }
end

def bulk_asn_lookup(ips, logger, workers: 40, timeout: 3)
  queue   = Queue.new
  ips.each { |ip| queue << ip }
  results = {}
  mutex   = Mutex.new
  threads = Array.new([workers, ips.size].min.clamp(1, workers)) do
    Thread.new do
      loop do
        ip = begin
          queue.pop(true)
        rescue ThreadError
          nil
        end
        break if ip.nil?
        info = asn_lookup(ip, timeout)
        mutex.synchronize { results[ip] = info }
      end
    end
  end
  threads.each(&:join)
  logger.info "ASN-resolved #{results.count { |_, v| v }}/#{ips.size} unique no-ptr IPs"
  results
end

# ============================================================================
# Load + parse archives
# ============================================================================
if ENV["DOMAINBLOCK_REPORT_ARCHIVE"]
  archives     = [ENV["DOMAINBLOCK_REPORT_ARCHIVE"]]
  archive_path = archives.last
  logger.info "DOMAINBLOCK_REPORT_ARCHIVE set — using #{archive_path} only " \
              "(persistence section will just cover this one file)"
else
  archives     = find_all_archives(SEEN_LOG_FILE, logger)
  archive_path = archives.last
end
exit 0 if archive_path.nil?
logger.info "Primary archive (this month): #{archive_path}"
logger.info "History available: #{archives.size} archive(s), #{File.basename(archives.first)}..#{File.basename(archives.last)}" if archives.size > 1

rows     = parse_archive(archive_path)                       # this month only — drives verdict counts + top-by-volume
all_rows = archives.size > 1 ? archives.flat_map { |a| parse_archive(a) } : rows  # full retained history — drives persistence
logger.info "#{rows.size} rows this month, #{all_rows.size} rows across full retained history"

verdict_counts = rows.each_with_object(Hash.new(0)) { |r, h| h[r[:verdict]] += 1 }

patterns = load_patterns(PATTERNS_PATH, logger)

# --- Top uncovered PTR suffixes this month, by volume -----------------------
suffix_hits = Hash.new(0)
suffix_ips  = Hash.new { |h, k| h[k] = Set.new }
rows.each do |r|
  next unless r[:verdict] == "no-match"
  next if r[:ptr].to_s.empty?
  suffix = r[:ptr].sub(/\A[^.]+\./, "") # strip one leftmost label, like the manual awk workflow
  suffix_hits[suffix] += 1
  suffix_ips[suffix] << r[:ip]
end

uncovered_suffixes = suffix_hits
                     .reject { |suffix, _| hostname_matches?("x.#{suffix}", patterns) }
                     .sort_by { |_, n| -n }
                     .first(REPORT_TOP_N)

# --- Persistent PTR suffixes across the FULL retained history, by distinct
# days seen — this is the "paces attempts to avoid volume-based detection"
# signal: something with only a handful of hits total but spread across many
# separate days won't rank anywhere near the top of the list above.
suffix_all_hits  = Hash.new(0)
suffix_all_ips   = Hash.new { |h, k| h[k] = Set.new }
suffix_all_dates = Hash.new { |h, k| h[k] = Set.new }
all_rows.each do |r|
  next unless r[:verdict] == "no-match"
  next if r[:ptr].to_s.empty?
  suffix = r[:ptr].sub(/\A[^.]+\./, "")
  suffix_all_hits[suffix] += 1
  suffix_all_ips[suffix] << r[:ip]
  suffix_all_dates[suffix] << r[:date]
end

persistent_suffixes = suffix_all_dates
                      .select { |_, dates| dates.size >= REPORT_MIN_DAYS }
                      .reject { |suffix, _| hostname_matches?("x.#{suffix}", patterns) }
                      .sort_by { |_, dates| -dates.size }
                      .first(REPORT_TOP_N)

# --- ASN names: resolve once from the UNION of no-ptr IPs across the full
# history, then use the same map for both the this-month and all-history views.
uncovered_asns      = []
persistent_asns     = []
if ASN_CHECK_ENABLED
  asn_patterns = load_patterns(ASN_PATTERNS_PATH, logger, label: "ASN patterns")
  noptr_ips_all = all_rows.select { |r| r[:verdict] == "no-ptr" }.map { |r| r[:ip] }.uniq

  if noptr_ips_all.any?
    asn_map = bulk_asn_lookup(noptr_ips_all, logger, timeout: DNS_TIMEOUT)

    # this month, by volume
    asn_hits = Hash.new(0)
    asn_ips  = Hash.new { |h, k| h[k] = Set.new }
    rows.each do |r|
      next unless r[:verdict] == "no-ptr"
      info = asn_map[r[:ip]]
      next unless info
      label = "AS#{info[:asn]} #{info[:name]}"
      asn_hits[label] += 1
      asn_ips[label] << r[:ip]
    end
    uncovered_asns = asn_hits
                     .reject { |label, _| asn_name_matches?(label.sub(/\AAS\d+ /, ""), asn_patterns) }
                     .sort_by { |_, n| -n }
                     .first(REPORT_TOP_N)

    # full history, by distinct days seen
    asn_all_hits  = Hash.new(0)
    asn_all_ips   = Hash.new { |h, k| h[k] = Set.new }
    asn_all_dates = Hash.new { |h, k| h[k] = Set.new }
    all_rows.each do |r|
      next unless r[:verdict] == "no-ptr"
      info = asn_map[r[:ip]]
      next unless info
      label = "AS#{info[:asn]} #{info[:name]}"
      asn_all_hits[label] += 1
      asn_all_ips[label] << r[:ip]
      asn_all_dates[label] << r[:date]
    end
    persistent_asns = asn_all_dates
                      .select { |_, dates| dates.size >= REPORT_MIN_DAYS }
                      .reject { |label, _| asn_name_matches?(label.sub(/\AAS\d+ /, ""), asn_patterns) }
                      .sort_by { |_, dates| -dates.size }
                      .first(REPORT_TOP_N)
  end
end

# ============================================================================
# Format the email body
# ============================================================================
month_label  = File.basename(archive_path)[/(\d{4}-\d{2})/, 1] || "unknown"
report_title = REPORT_SUBJECT_TEMPLATE.gsub("%{month}", month_label)

body = +""
body << "#{report_title}\n"
body << "Archive analyzed: #{archive_path}\n"
if archives.size > 1
  body << "History available for persistence check: #{archives.size} archive(s), " \
          "#{File.basename(archives.first)}..#{File.basename(archives.last)}\n"
end
body << "Total rows this month: #{rows.size}\n\n"
body << "Verdicts (this month):\n"
%w[banned-ptr banned-asn no-match no-ptr].each do |v|
  body << format("  %-10s %d\n", v, verdict_counts[v] || 0)
end
body << "\n"
body << "This is a MECHANICAL coverage report, not a verdict — it flags what's new\n"
body << "and how much volume it represents, ranked by hits. Deciding whether\n"
body << "something is a benign scanner, a bulletproof host, or an ISP you should\n"
body << "leave alone still takes an actual look before adding anything below.\n\n"

body << "=== Top #{uncovered_suffixes.size} PTR suffixes NOT in domainblock-patterns.txt (this month, by volume) ===\n"
if uncovered_suffixes.empty?
  body << "(none — every no-match suffix this month is already covered)\n"
else
  uncovered_suffixes.each do |suffix, hits|
    body << format("  %6d hits  %5d unique IPs   %s\n", hits, suffix_ips[suffix].size, suffix)
  end
end
body << "\n"

if ASN_CHECK_ENABLED
  body << "=== Top #{uncovered_asns.size} ASN names NOT in domainblock-asn-patterns.txt (this month, by volume) ===\n"
  if uncovered_asns.empty?
    body << "(none — every resolved ASN this month is already covered, or no-ptr bucket was empty)\n"
  else
    uncovered_asns.each do |label, hits|
      body << format("  %6d hits   %s\n", hits, label)
    end
  end
else
  body << "(asn_check is off in config.yml — no-ptr bucket wasn't broken down by ASN.)\n"
end
body << "\n"

body << "=== Persistent PTR suffixes: #{REPORT_MIN_DAYS}+ distinct days seen, full retained history ===\n"
body << "(low-and-slow signal — spread across many separate days rather than\n"
body << " clustered, so it may never rank near the top of the volume list above\n"
body << " even though the same source keeps coming back)\n"
if persistent_suffixes.empty?
  body << "(none met the #{REPORT_MIN_DAYS}-day threshold" \
          "#{archives.size == 1 ? ' — only one archive available so far, check back next month' : ''})\n"
else
  persistent_suffixes.each do |suffix, dates|
    body << format("  %3d distinct days  %6d hits total  %5d unique IPs   %s\n",
                    dates.size, suffix_all_hits[suffix], suffix_all_ips[suffix].size, suffix)
  end
end
body << "\n"

if ASN_CHECK_ENABLED
  body << "=== Persistent ASN names: #{REPORT_MIN_DAYS}+ distinct days seen, full retained history ===\n"
  if persistent_asns.empty?
    body << "(none met the #{REPORT_MIN_DAYS}-day threshold" \
            "#{archives.size == 1 ? ' — only one archive available so far, check back next month' : ''})\n"
  else
    persistent_asns.each do |label, dates|
      body << format("  %3d distinct days  %6d hits total  %5d unique IPs   %s\n",
                      dates.size, asn_all_hits[label], asn_all_ips[label].size, label)
    end
  end
end
body << "\n"

# --- Paste-ready blocks: pattern lines with a "# reason" comment on its OWN
# line directly above each one — never inline after the pattern, since
# load_patterns only skips a line that STARTS with '#'; a trailing comment
# gets parsed as part of the literal pattern and silently never matches
# anything. Reasons are combined per final pattern (not per raw label), so
# two ASNs that share one AS Name — e.g. Cloudflare's AS13335 and AS14789 —
# get one pattern line with two contributing reasons above it, not a
# duplicated pattern. ---------------------------------------------------
suffix_reasons = Hash.new { |h, k| h[k] = [] }
uncovered_suffixes.each do |suffix, hits|
  suffix_reasons[suffix] << "#{hits} hits, #{suffix_ips[suffix].size} unique IPs this month"
end
persistent_suffixes.each do |suffix, dates|
  suffix_reasons[suffix] << "#{dates.size} distinct days over full history (low-and-slow), " \
                             "#{suffix_all_hits[suffix]} hits total, #{suffix_all_ips[suffix].size} unique IPs"
end
paste_suffixes = suffix_reasons.keys.sort

asn_pattern_reasons = Hash.new { |h, k| h[k] = [] }
uncovered_asns.each do |label, hits|
  asn_pattern_reasons[asn_pattern_from_label(label)] << "#{label}: #{hits} hits this month"
end
persistent_asns.each do |label, dates|
  asn_pattern_reasons[asn_pattern_from_label(label)] <<
    "#{label}: #{dates.size} distinct days over full history (low-and-slow), #{asn_all_hits[label]} hits total"
end
paste_asns = asn_pattern_reasons.keys.sort

body << "=== Paste-ready additions for domainblock-patterns.txt (#{paste_suffixes.size}, deduplicated) ===\n"
if paste_suffixes.empty?
  body << "(nothing new to add)\n"
else
  paste_suffixes.each do |suffix|
    suffix_reasons[suffix].each { |reason| body << "# #{reason}\n" }
    body << "*.#{suffix}\n"
  end
end
body << "\n"

if ASN_CHECK_ENABLED
  body << "=== Paste-ready additions for domainblock-asn-patterns.txt (#{paste_asns.size}, deduplicated) ===\n"
  if paste_asns.empty?
    body << "(nothing new to add)\n"
  else
    paste_asns.each do |pattern|
      asn_pattern_reasons[pattern].each { |reason| body << "# #{reason}\n" }
      body << "#{pattern}\n"
    end
  end
end

# ============================================================================
# Send (or print, in dry-run)
# ============================================================================
if DRY_RUN
  puts body
  logger.info "DOMAINBLOCK_DRYRUN=1 — printed report instead of emailing"
  exit 0
end

if REPORT_FROM.nil? || REPORT_TO.nil? || SMTP_HOST.nil?
  logger.error "report_from / report_to / report_smtp_host must be set in config.yml to send email"
  exit 1
end

# report_to may be a single address or a comma-separated list — split it so
# each recipient becomes its own RCPT TO rather than one malformed address.
to_addrs = REPORT_TO.to_s.split(",").map(&:strip).reject(&:empty?)

msg = <<~MSG
  From: #{REPORT_FROM}
  To: #{to_addrs.join(", ")}
  Subject: #{report_title}
  Content-Type: text/plain; charset=UTF-8
  Content-Transfer-Encoding: 8bit

  #{body}
MSG

begin
  smtp = Net::SMTP.new(SMTP_HOST, SMTP_PORT)
  smtp.enable_starttls_auto if SMTP_STARTTLS
  if SMTP_USER && SMTP_PASS
    smtp.start("localhost", SMTP_USER, SMTP_PASS, :login) do |s|
      s.send_message(msg, REPORT_FROM, to_addrs)
    end
  else
    smtp.start("localhost") do |s|
      s.send_message(msg, REPORT_FROM, to_addrs)
    end
  end
  logger.info "Report emailed to #{to_addrs.join(', ')}"
rescue StandardError => e
  logger.error "Failed to send report email: #{e.class}: #{e.message}"
  exit 1
end
