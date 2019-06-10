#!/bin/perl

#preprocess regular status output with this and feed to graph-by-time2crack.py

#Recovered........: 200/6119
#Recovered........: 2/819

$total=0;
$tick=0;
while ($line=<STDIN>) {

    if ($line=~m!Recovered\.\.\.\.\.\.\.\.: (\d+)/(\d+) !) {
        $preva=$a;
        $a=$1;
        $b=$2;

        if ($total>$b) {            $sum+=$preva; $total=$b;    }

        $tick++;

        if ($total<$b) {
            $total=$b;
            print "$total\n";
        }

        $v=$a+$sum;
        print "$v\n";

    }
}
