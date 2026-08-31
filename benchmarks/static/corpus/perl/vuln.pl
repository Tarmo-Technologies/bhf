sub h {
    my $o = `ls $d`;      # EXPECT BHF-404
    system("rm " . $a);   # EXPECT BHF-404
    my $r = eval "$code"; # EXPECT BHF-420
    my $x = md5_hex($d);  # EXPECT BHF-422
    my $api_key = "AKIAsecretvalue1234"; # EXPECT BHF-429
}
