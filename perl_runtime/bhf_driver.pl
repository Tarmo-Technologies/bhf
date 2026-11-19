# SPDX-License-Identifier: Apache-2.0
# bhf Perl fork-server driver. Run under `perl -d:BhfCov` so DB::DB records
# edge coverage into the shared BHF_COV_SHM map. Speaks the BHF_FRAMED
# protocol (matches c_runtime/bhf_driver.c): fd 1 control pipe, fd 0 input pipe
# ({u32 LE len, bytes}). A finding die()s -> stderr marker + exit 86 (no sync byte);
# an expected rejection (input validation / a library's own exception object) is
# swallowed. No third-party fuzzer.
use strict;
use warnings;
require Devel::BhfCov;

my $FINDING_HALT = 86;
# Top package of the target (set by the launcher): a blessed exception object whose
# class is in the target's own namespace is that library's declared rejection, not
# a bhf finding (the Ada/Java "declared exception" principle).
# M22: `defined(..) ? .. : ..` not the `//` defined-or operator, so this driver
# runs on Perl 5.6-5.9 (legacy gov/mil) where `//` is a syntax error (5.10+).
my $TARGET_PKG = defined($ENV{BHF_TARGET_PACKAGE}) ? $ENV{BHF_TARGET_PACKAGE} : '';
my @EXPECTED = grep { length } split /,/,
    (defined($ENV{BHF_EXPECTED_EXCEPTIONS}) ? $ENV{BHF_EXPECTED_EXCEPTIONS} : '');

my $harness = $ENV{BHF_HARNESS} or die "BHF_HARNESS unset\n";
require $harness;

# A die message that reads like input validation, not a bug. Mirrors the Python
# lane's ValueError/declared-exception suppression. Perl's croak-on-bad-input
# convention produces these.
# Perl uses `die` as ordinary error handling — a plain string die is almost always
# the program REJECTING bad input (the croak-on-bad-args convention), not a bug. So
# (FP-avoidant, like the Python untyped policy) we report ONLY high-confidence
# bug-class dies and suppress everything else. This lane has no behavioral sink
# oracles yet (the runtrace shim is not loaded into perl). Returns the CWE, or ''
# for a generic die (= not a finding). A user can force-report a message via BHF_EXPECTED... no
# — @EXPECTED here SUPPRESSES named messages (a target's known internal die text).
sub bug_cwe {
    my ($msg) = @_;
    for my $e (@EXPECTED) { return '' if length($e) && index($msg, $e) >= 0; }
    return 'CWE-674' if $msg =~ /deep recursion/i;
    return 'CWE-789' if $msg =~ /out of memory|can't allocate/i;
    return 'CWE-369' if $msg =~ /division by zero|illegal division|illegal modulus/i;
    return 'CWE-617'
        if $msg
        =~ /\b(panic|assert(ion)?|invariant|unreachable|internal error|should (never|not) (happen|be reached|occur)|impossible|corrupt)\b/i;
    return '';    # generic die = normal Perl error handling, suppressed
}

# The target's frames at the last die, innermost first, as `function @ file:line`
# (at most 5), without this driver's and the harness's own frames. A __DIE__ hook
# records them where the die happened; the message's own `at FILE line N` is
# trimmed from the finding line.
my @DIE_FRAMES;
sub capture_die_frames {
    @DIE_FRAMES = ();
    # Frame $i is where the sub named by frame $i + 1 was running.
    # The coverage hook (DB::DB) runs inside the target's statements.
    my $coverage = defined($INC{'Devel/BhfCov.pm'}) ? $INC{'Devel/BhfCov.pm'} : '';
    for (my $i = 0; my @here = caller($i); $i++) {
        next if $here[1] eq __FILE__ || $here[1] eq $harness || $here[1] =~ /^\(eval/;
        next if $here[1] eq $coverage;
        my @in = caller($i + 1);
        my $function = @in ? $in[3] : 'main';
        push @DIE_FRAMES, "$function @ $here[1]:$here[2]";
        last if @DIE_FRAMES >= 5;
    }
}

# In bhf's re-run of an input that hung, print the frames the target is
# running once the run reaches BHF_HANG_REPORT_MS, then halt: bhf keys the hang
# finding on them. Perl runs a signal's handler between ops, so SIGALRM's
# interrupts a target looping in Perl where it loops.
sub arm_hang_report {
    my $after = $ENV{BHF_HANG_REPORT_MS};
    return unless defined($after) && $after =~ /^\d+$/ && $after > 0;
    my $hires = eval { require Time::HiRes; 1 };
    my $left = $after / 1000 - (time() - $^T);
    $left = 0.001 if $left <= 0;
    $SIG{ALRM} = sub {
        capture_die_frames();
        print STDERR "== bhf hang: perl\n";
        print STDERR "== bhf frame: $_\n" for @DIE_FRAMES;
        require POSIX;
        POSIX::_exit($FINDING_HALT);
    };
    if ($hires) {
        Time::HiRes::alarm($left);
    } else {
        alarm(int($left + 0.999));
    }
}

# The file the runtrace shim reads the current input from, when bhf preloads
# it (#300): the shim cannot see this process's bytes otherwise, so a sink the
# target reached could not be traced back to the input. One per process, since
# bhf runs fresh processes beside this one; removed at exit.
my $SHIM_INPUT_FILE =
    (defined $ENV{BHF_SHIM_INPUT_FILE} && length $ENV{BHF_SHIM_INPUT_FILE})
    ? "$ENV{BHF_SHIM_INPUT_FILE}.$$"
    : undef;
my $SHIM_INPUT_PID = $$;
END { unlink $SHIM_INPUT_FILE if defined $SHIM_INPUT_FILE && $$ == $SHIM_INPUT_PID; }

sub publish_input {
    my ($data) = @_;
    return if !defined $SHIM_INPUT_FILE;
    open(my $fh, '>:raw', $SHIM_INPUT_FILE) or return;
    print $fh $data;
    close($fh);
}

sub run_input {
    my ($data) = @_;
    Devel::BhfCov::reset_prev();
    publish_input($data);
    @DIE_FRAMES = ();
    my $ok = eval {
        local $SIG{__DIE__} = \&capture_die_frames;
        bhfgen::bhf_run_one($data);
        1;
    };
    return if $ok;
    my $err = $@;
    # A blessed exception object from the target's own package is a declared
    # rejection (e.g. My::Parser::Error), not a finding.
    if (ref $err) {
        my $class = ref $err;
        return if length($TARGET_PKG) && index($class, $TARGET_PKG) == 0;
        my $cwe = bug_cwe("$err");
        report_finding($cwe, "$class: $err") if $cwe;
        return;
    }
    my $cwe = bug_cwe("$err");
    report_finding($cwe, "$err") if $cwe;
}

sub report_finding {
    my ($cwe, $msg) = @_;
    $msg =~ s/\s+at .* line \d+\.?$//;    # trim the "at FILE line N" suffix
    # Marker mirrors the JVM/Python drivers; the engine's parse_perl_finding maps
    # the CWE token to a BHF rule.
    print STDERR "== bhf perl finding: $cwe: $msg\n";
    print STDERR "== bhf frame: $_\n" for @DIE_FRAMES;
    exit($FINDING_HALT);
}

sub read_exact {
    my ($n) = @_;
    my $buf = '';
    while (length($buf) < $n) {
        my $r = sysread(STDIN, my $chunk, $n - length($buf));
        return undef if !defined($r) || $r == 0;
        $buf .= $chunk;
    }
    return $buf;
}

binmode STDIN;
if (defined $ENV{BHF_FRAMED}) {
    # Save the control pipe (fd 1) then redirect STDOUT to /dev/null so the target's
    # prints can't corrupt the sync stream (#427).
    open(my $CTL, '>&', \*STDOUT) or die "dup control: $!\n";
    binmode $CTL;
    $CTL->autoflush(1);
    require File::Spec;
    open(STDOUT, '>', File::Spec->devnull) or die "redirect stdout: $!\n";
    syswrite($CTL, "\x01");    # ready byte
    my $count = 0;
    while (1) {
        my $hdr = read_exact(4);
        last if !defined $hdr;
        my $n = unpack('V', $hdr);
        my $data = $n > 0 ? read_exact($n) : '';
        last if !defined $data;
        run_input($data);
        Devel::BhfCov::flush();
        syswrite($CTL, "\x01");    # sync byte
        # Periodically persist covered lines for negative fuzz-confirmation (no-op
        # unless the set grew / BHF_COVERED_LINES is set; coverage plateaus).
        ++$count;
        # Exponentially spaced early checkpoints keep short campaigns from
        # losing all line evidence before the old 512-input checkpoint.
        Devel::BhfCov::dump_covered_lines()
            if (($count & ($count - 1)) == 0 || ($count & 0x1FF) == 0);
    }
} else {
    arm_hang_report();
    my $data;
    if (@ARGV && -f $ARGV[0]) {
        local $/;
        open(my $f, '<', $ARGV[0]) or die "open $ARGV[0]: $!\n";
        binmode $f;
        $data = <$f>;
    } else {
        local $/;
        $data = <STDIN>;
    }
    run_input(defined($data) ? $data : '');
    Devel::BhfCov::flush();
}
Devel::BhfCov::dump_covered_lines();
