#! /usr/bin/perl

use strict;
use warnings;

#
# my_mtrace_depth2.pl — Decode and analyze depth-N __malloc_hook log
#
# Usage:
#   perl my_mtrace_depth2.pl <mtrace2_log_file> [maps_file]
#
# Log format produced by mtrace_watcher.c (dn_log_event):
#   @ <f1>:[0xA1];<f2>:[0xA2];...;<fN>:[0xAN] + 0xPTR 0xSIZE   (alloc)
#   @ <f1>:[0xA1];...                           - 0xPTR 0x0     (free)
#
# Output sections:
#   1. Per-call-stack aggregation  — top leak sites by total leaked bytes
#   2. Individual unfreed allocations sorted by size descending
#   3. addr2line commands to resolve lib:[0xOFFSET] on host
#
# If maps_file (/proc/<pid>/maps snapshot) is supplied, base addresses for
# each library are extracted and addr2line commands are emitted automatically.
#

if ($#ARGV < 0 || $#ARGV > 1) {
    die "Usage: $0 <mtrace2_log_file> [maps_file]\n";
}

my $data      = $ARGV[0];
my $maps_file = $ARGV[1] // '';

open(my $fh, '<', $data) or die "Cannot open $data: $!\n";

my %allocated;      # ptr -> { size, frames[] }
my $events    = 0;
my $alloc_ev  = 0;
my $free_ev   = 0;
my $max_depth = 0;

# -----------------------------------------------------------------------
# Pass 1: parse log and track live allocations
# -----------------------------------------------------------------------
while (my $line = <$fh>) {
    chomp $line;
    next if $line =~ /^\s*$/ || $line =~ /^#/;
    $events++;

    # Format: @ frame0[;frame1...] op 0xPTR 0xSIZE
    if ($line =~ /^\@\s+(\S+)\s+([+-])\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)$/) {
        my ($frames_str, $op, $ptr, $size_hex) = ($1, $2, $3, $4);
        my @frames = split(/;/, $frames_str);
        my $depth  = scalar @frames;
        $max_depth = $depth if $depth > $max_depth;

        if ($op eq '+') {
            $allocated{$ptr} = { size => hex($size_hex), frames => \@frames };
            $alloc_ev++;
        } elsif ($op eq '-') {
            delete $allocated{$ptr};
            $free_ev++;
        }
    }
}
close($fh);

printf "Events processed : %d  (allocs: %d  frees: %d)\n", $events, $alloc_ev, $free_ev;
printf "Max frame depth  : %d\n", $max_depth;
printf "Unfreed allocs   : %d\n\n", scalar keys %allocated;

my @live_ptrs = keys %allocated;
if (!@live_ptrs) {
    print "No memory leaks detected.\n";
    exit 0;
}

# -----------------------------------------------------------------------
# Pass 2: aggregate by call-stack key
# -----------------------------------------------------------------------
my %by_stack;   # stack_key -> { count, total, frames[] }

foreach my $ptr (@live_ptrs) {
    my $entry     = $allocated{$ptr};
    my @frames    = @{ $entry->{frames} };
    my $stack_key = join(';', @frames);

    if (!exists $by_stack{$stack_key}) {
        $by_stack{$stack_key} = { count => 0, total => 0, frames => \@frames };
    }
    $by_stack{$stack_key}{count}++;
    $by_stack{$stack_key}{total} += $entry->{size};
}

# -----------------------------------------------------------------------
# Section 1: Top leak sites aggregated by call-stack
# -----------------------------------------------------------------------
my @stacks_sorted = sort { $by_stack{$b}{total} <=> $by_stack{$a}{total} }
                    keys %by_stack;

my $total_leaked = 0;
$total_leaked += $by_stack{$_}{total} for @stacks_sorted;

printf "=" x 72 . "\n";
printf " TOP LEAK SITES (aggregated by call-stack, sorted by total bytes)\n";
printf " Total leaked: %d bytes  |  %d unique call-stacks\n",
       $total_leaked, scalar @stacks_sorted;
printf "=" x 72 . "\n\n";

my $rank = 0;
foreach my $key (@stacks_sorted) {
    $rank++;
    my $s   = $by_stack{$key};
    my @frs = @{ $s->{frames} };
    my $avg = int($s->{total} / ($s->{count} || 1));

    printf "#%-3d  %d allocs  |  %d bytes total  |  avg %d bytes/alloc\n",
           $rank, $s->{count}, $s->{total}, $avg;
    for my $i (0 .. $#frs) {
        printf "      Frame %-2d: %s\n", $i + 1, $frs[$i];
    }
    print "\n";
    last if $rank >= 20;   # show top 20 leak sites
}

# -----------------------------------------------------------------------
# Section 2: Individual unfreed allocations sorted by size descending
# -----------------------------------------------------------------------
my @sorted_ptrs = sort { $allocated{$b}{size} <=> $allocated{$a}{size} } @live_ptrs;

printf "=" x 72 . "\n";
printf " INDIVIDUAL UNFREED ALLOCATIONS (top 50, sorted by size)\n";
printf "=" x 72 . "\n";

my $hdr = sprintf("%-18s  %-11s", "Address", "Size(bytes)");
for my $d (1 .. $max_depth) {
    $hdr .= sprintf("  %-35s", "Caller$d");
}
printf "%s\n", $hdr;
printf "-" x length($hdr) . "\n";

my $shown = 0;
foreach my $ptr (@sorted_ptrs) {
    my $e   = $allocated{$ptr};
    my @frs = @{ $e->{frames} };
    my $row = sprintf("%-18s  %-11d", $ptr, $e->{size});
    for my $d (0 .. $max_depth - 1) {
        my $tok = defined($frs[$d]) ? $frs[$d] : '-';
        $row .= sprintf("  %-35s", $tok);
    }
    print "$row\n";
    last if ++$shown >= 50;
}
printf "\nTotal leaked: %d bytes\n", $total_leaked;

# -----------------------------------------------------------------------
# Section 3: addr2line resolution guide
# -----------------------------------------------------------------------
printf "\n" . "=" x 72 . "\n";
printf " HOW TO RESOLVE lib:[0xOFFSET] TO FUNCTION:FILE:LINE\n";
printf "=" x 72 . "\n";

# Collect unique lib:offset tokens from live allocations only
my %seen_tokens;
foreach my $ptr (@live_ptrs) {
    for my $tok (@{ $allocated{$ptr}{frames} }) {
        next if $tok =~ /^\[unknown\]/ || $tok eq '-';
        $seen_tokens{$tok} = 1;
    }
}

# Group offsets by library name
my %lib_offsets;   # libname -> [ offset, ... ]
foreach my $tok (sort keys %seen_tokens) {
    if ($tok =~ /^(.+):\[(0x[0-9a-fA-F]+)\]$/) {
        my ($lib, $off) = ($1, $2);
        my $already = grep { $_ eq $off } @{ $lib_offsets{$lib} // [] };
        push @{ $lib_offsets{$lib} }, $off unless $already;
    }
}

# Load maps file for load base addresses if provided
my %lib_base;   # libname (basename) -> base address hex string
if ($maps_file && -f $maps_file) {
    open(my $mf, '<', $maps_file) or warn "Cannot open maps: $maps_file\n";
    while (my $mline = <$mf>) {
        # b6700000-b6800000 r-xp 00000000 b3:09 1234  /usr/lib/libfoo.so.1
        if ($mline =~ /^([0-9a-f]+)-[0-9a-f]+\s+r-xp\s+\S+\s+\S+\s+\S+\s+(\S+)/) {
            my ($base, $path) = ($1, $2);
            my $bn = $path; $bn =~ s|.*/||;
            $lib_base{$bn} //= "0x$base";
        }
    }
    close($mf);
    printf "Maps file used   : %s\n\n", $maps_file;
} else {
    printf "No maps file — offsets shown as-is (relative to load base).\n";
    printf "Pass /proc/<pid>/maps snapshot as 2nd arg for base addresses.\n\n";
}

printf "On the build HOST with debug sysroot:\n\n";
foreach my $lib (sort keys %lib_offsets) {
    my @offs      = @{ $lib_offsets{$lib} };
    my $base_note = exists $lib_base{$lib} ? "  (maps base: $lib_base{$lib})" : '';
    printf "  # %s%s\n", $lib, $base_note;
    printf "  addr2line -f -i -e <dbg-sysroot>/usr/lib/%s \\\n", $lib;
    printf "    %s\n\n", join(" \\\n    ", @offs);
}
printf "  Tip: -f shows function name, -i shows inlined frames.\n";
