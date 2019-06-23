#!/bin/perl

while ($line=<STDIN>) {

    chomp($line);
    ($a,$b,$c,$d,$e,$f,$g,$h,$i,$j,$k)=split(m/,/,$line,11);

    $j=~s/"//;

    if ($j=~m/(..)(.{32})/) {
        $salt=$1;
        $hash=$2;
        print "$hash:$salt\n";
    }
}
