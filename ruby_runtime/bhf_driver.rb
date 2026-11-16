# SPDX-License-Identifier: Apache-2.0
# bhf Ruby fork-server driver. A TracePoint(:line) records edge coverage into the
# shared BHF_COV_SHM map. Speaks the BHF_FRAMED protocol (matches
# c_runtime/bhf_driver.c and the Perl driver): fd 1 control pipe, fd 0 input pipe
# ({u32 LE len, bytes}). A finding raises -> stderr marker + exit 86 (no sync byte);
# an expected rejection (input validation / a library's own exception class) is
# swallowed. No third-party fuzzer.

FINDING_HALT = 86
# The declared-rejection namespace: an exception whose class is defined in the
# target's own top module (e.g. Toml::ParseError) is that library's rejection, not a
# bhf finding (the Ada/Java/Perl "declared exception" principle).
TARGET_MODULE = ENV['BHF_TARGET_MODULE'].to_s
EXPECTED = (ENV['BHF_EXPECTED_EXCEPTIONS'] || '').split(',').reject(&:empty?)

# ---- Coverage: a TracePoint(:line) folded into a 64KB AFL-style edge bitmap. ----
COV_BITS = 1 << 16
COV_MASK = COV_BITS - 1
$cov_map = ("\0".b * COV_BITS)
$cov_prev = 0
$cov_prefix = ENV['BHF_TRACE_PREFIX'].to_s
$covered = {}
$covered_dumped = 0

def bhf_fnv(str, line)
  h = 0x811c9dc5
  str.each_byte { |c| h = ((h ^ c) * 0x01000193) & 0xFFFFFFFF }
  h = ((h ^ (line & 0xFF)) * 0x01000193) & 0xFFFFFFFF
  h = ((h ^ ((line >> 8) & 0xFF)) * 0x01000193) & 0xFFFFFFFF
  h & COV_MASK
end

COV_TP = TracePoint.new(:line) do |tp|
  path = tp.path
  next if !$cov_prefix.empty? && !path.start_with?($cov_prefix)
  $covered["#{path}:#{tp.lineno}"] = true
  block = bhf_fnv(path, tp.lineno)
  idx = ($cov_prev ^ block) & COV_MASK
  v = $cov_map.getbyte(idx)
  $cov_map.setbyte(idx, v + 1) if v < 0xFF
  $cov_prev = (block >> 1) & COV_MASK
end

def bhf_reset_prev
  $cov_prev = 0
end

def bhf_flush_cov
  path = ENV['BHF_COV_SHM']
  return if path.nil? || path.empty?
  begin
    File.open(path, File::RDWR | File::CREAT) do |f|
      f.binmode
      f.seek(0)
      f.write($cov_map)
    end
  rescue StandardError
    # best-effort
  end
end

def bhf_dump_covered
  path = ENV['BHF_COVERED_LINES']
  return if path.nil? || path.empty?
  n = $covered.size
  return if n == $covered_dumped
  begin
    File.write("#{path}.tmp", $covered.keys.sort.join("\n"))
    File.rename("#{path}.tmp", path)
    $covered_dumped = n
  rescue StandardError
    # best-effort
  end
end

# ---- Finding classification (FP-avoidant, like the Python/Perl/JS lanes). ----
# Only high-confidence bug-class exceptions are findings; Ruby's normal input-
# rejection errors (ArgumentError/TypeError/KeyError/IndexError/NoMethodError/...) are
# suppressed. This lane has no behavioral sink oracles yet (the runtrace shim is
# not loaded into ruby), so an injection that raises nothing is not reported.
def bhf_bug_cwe(err)
  case err
  when ZeroDivisionError then 'CWE-369'
  when SystemStackError then 'CWE-674' # unbounded recursion / stack exhaustion
  when NoMemoryError then 'CWE-789'    # uncontrolled memory allocation
  else
    msg = err.message.to_s
    if err.is_a?(RuntimeError) &&
       msg =~ /\b(assert(ion)?|invariant|unreachable|internal error|should (never|not) (happen|be reached|occur)|impossible|bug|corrupt)\b/i
      'CWE-617'
    end
  end
end

def bhf_report_finding(cwe, msg, err = nil)
  msg = msg.to_s.gsub(/\s+/, ' ').strip
  # Marker mirrors the Perl/Python/JVM drivers; the engine's parse_ruby_finding maps
  # the CWE token to a BHF rule.
  $stderr.puts "== bhf ruby finding: #{cwe}: #{msg}"
  bhf_target_frames(err).each { |frame| $stderr.puts "== bhf frame: #{frame}" } if err
  $stderr.flush
  exit(FINDING_HALT)
end

# The target's frames of err, innermost first, as `function @ file:line` (at most
# 5), without this driver's and the harness's own frames. A SystemStackError's
# backtrace is the deep end of the recursion, which is the target's.
def bhf_target_frames(err)
  frames = bhf_location_frames(err.backtrace_locations || [])
  if frames.empty?
    skip = bhf_own_paths
    (err.backtrace || []).each do |line|
      m = line.match(/\A(.+):(\d+):in [`'](.+)'\z/) or next
      next if skip.include?(File.expand_path(m[1]))
      frames << "#{m[3]} @ #{m[1]}:#{m[2]}"
      break if frames.size >= 5
    end
  end
  frames
end

def bhf_own_paths
  [File.expand_path(__FILE__), File.expand_path(ENV['BHF_HARNESS'].to_s)]
end

# `function @ file:line` of the target's frames among `locations` (at most 5).
def bhf_location_frames(locations)
  skip = bhf_own_paths
  frames = []
  locations.each_with_index do |loc, i|
    path = loc.absolute_path || loc.path
    next if path.nil? || path.start_with?('<internal:') || skip.include?(File.expand_path(path))
    # A C method (`Integer#/`) is reported at the line that called it, which
    # the next frame names too: that frame's method is the target's.
    caller_frame = locations[i + 1]
    next if caller_frame && caller_frame.lineno == loc.lineno &&
            (caller_frame.absolute_path || caller_frame.path) == path
    frames << "#{loc.label} @ #{path}:#{loc.lineno}"
    break if frames.size >= 5
  end
  frames
end

# In bhf's re-run of an input that hung, print the frames the target is
# running once the run reaches BHF_HANG_REPORT_MS, then halt: bhf keys the hang
# finding on them. A watchdog thread keeps the time; Ruby switches threads
# while the target loops, so it reads the main thread's stack where it loops.
def bhf_arm_hang_report
  after = Integer(ENV['BHF_HANG_REPORT_MS'] || '', exception: false)
  return unless after&.positive?
  main = Thread.current
  started = Process.clock_gettime(Process::CLOCK_MONOTONIC) - bhf_process_age
  watchdog = Thread.new do
    left = started + after / 1000.0 - Process.clock_gettime(Process::CLOCK_MONOTONIC)
    sleep(left) if left.positive?
    frames = bhf_location_frames(main.backtrace_locations || [])
    lines = ['== bhf hang: ruby'] + frames.map { |frame| "== bhf frame: #{frame}" }
    $stderr.write(lines.join("\n") + "\n")
    $stderr.flush
    exit!(FINDING_HALT)
  end
  watchdog.report_on_exception = false
end

# Seconds this process has run, so the watchdog counts from its start.
def bhf_process_age
  Process.clock_gettime(Process::CLOCK_PROCESS_CPUTIME_ID)
rescue StandardError
  0.0
end

def bhf_handle_error(err)
  cls = err.class.name.to_s
  # A blessed exception from the target's own module is a declared rejection.
  return if !TARGET_MODULE.empty? && cls.start_with?("#{TARGET_MODULE}::")
  return if EXPECTED.any? { |x| !x.empty? && err.message.to_s.include?(x) }
  cwe = bhf_bug_cwe(err)
  bhf_report_finding(cwe, "#{cls}: #{err.message}", err) if cwe
end

def bhf_run_input(data)
  bhf_reset_prev
  begin
    bhf_run_one(data)
  rescue SystemExit, SignalException
    raise
  rescue Exception => e
    bhf_handle_error(e)
  end
end

def bhf_read_exact(io, n)
  buf = ''.b
  while buf.bytesize < n
    chunk = io.read(n - buf.bytesize)
    return nil if chunk.nil? || chunk.empty?
    buf << chunk
  end
  buf
end

# ---- Load the target harness (defines bhf_run_one). ----
harness = ENV['BHF_HARNESS'] or abort 'BHF_HARNESS unset'
require harness

$stdin.binmode
COV_TP.enable

if ENV.key?('BHF_FRAMED')
  # Save the control pipe (fd 1) then redirect $stdout to /dev/null so the target's
  # prints can't corrupt the sync stream (#427).
  ctl = $stdout.dup
  ctl.binmode
  ctl.sync = true
  $stdout.reopen(File.open(File::NULL, 'w'))
  ctl.write("\x01") # ready byte
  count = 0
  loop do
    hdr = bhf_read_exact($stdin, 4)
    break if hdr.nil?
    n = hdr.unpack1('V')
    data = n > 0 ? bhf_read_exact($stdin, n) : ''.b
    break if data.nil?
    bhf_run_input(data)
    bhf_flush_cov
    ctl.write("\x01") # sync byte
    count += 1
    # Exponentially spaced early checkpoints keep short campaigns from losing
    # all line evidence before the old 512-input checkpoint.
    bhf_dump_covered if (count & (count - 1)).zero? || (count & 0x1FF).zero?
  end
else
  bhf_arm_hang_report
  data =
    if ARGV[0] && File.file?(ARGV[0])
      File.binread(ARGV[0])
    else
      $stdin.read
    end
  bhf_run_input(data || ''.b)
  bhf_flush_cov
end
bhf_dump_covered
