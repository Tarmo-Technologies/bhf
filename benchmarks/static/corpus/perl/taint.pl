# M23 Phase 2: interprocedural taint for Perl. Parameters bind from @_ in the
# body (not the header). A source-like @_ argument reaching a shell sink
# (system/exec/backticks/qx) is BHF-304, superseding the always-on BHF-404 heuristic.
sub run {
    my ($user_input) = @_;
    system($user_input);        # EXPECT BHF-304
}

sub dispatch {
    my ($user_query) = @_;
    forward($user_query);
}

sub forward {
    my ($arg) = @_;
    system($arg);               # EXPECT BHF-304
}

sub clean {
    my ($user_path) = @_;
    my $v = shell_quote($user_path);
    system($v);                 # EXPECT BHF-404
}
