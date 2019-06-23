#!/bin/perl
use MIME::Base64 qw/decode_base64/;

while ($source=<STDIN>) { 

    chomp($source);
    my $res = unpack('H*', decode_base64($source));

    $a=substr $res, 0, 8 ; 
    $b=substr $res, 8 ;
    
    print "$b:$a\n";
}
