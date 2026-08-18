#! /usr/bin/perl
eval "exec /usr/bin/perl -S $0 $@"
    if 0;
# Copyright (C) 1997-2024 Free Software Foundation, Inc.
# This file is part of the GNU C Library.
# Based on the mtrace.awk script.

# The GNU C Library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.

# The GNU C Library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public
# License along with the GNU C Library; if not, see
# <https://www.gnu.org/licenses/>.

$VERSION = "2.39";
$PKGVERSION = "(Ubuntu GLIBC 2.39-0ubuntu8.5) ";
$REPORT_BUGS_TO = '<https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>';
$progname = $0;

sub usage {
    print "Usage: mtrace [OPTION]... [Binary] MtraceData\n";
    print "  --help       print this help, then exit\n";
    print "  --version    print version number, then exit\n";
    print "\n";
    print "For bug reporting instructions, please see:\n";
    print "$REPORT_BUGS_TO.\n";
    exit 0;
}

# We expect two arguments:
#   #1: the complete path to the binary
#   #2: the mtrace data filename
# The usual options are also recognized.

arglist: while (@ARGV) {
    if ($ARGV[0] eq "--v" || $ARGV[0] eq "--ve" || $ARGV[0] eq "--ver" ||
        $ARGV[0] eq "--vers" || $ARGV[0] eq "--versi" ||
        $ARGV[0] eq "--versio" || $ARGV[0] eq "--version") {
        print "mtrace $PKGVERSION$VERSION\n";
        print "Copyright (C) 2024 Free Software Foundation, Inc.\n";
        print "This is free software; see the source for copying conditions.  There is NO\n";
        print "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n";
        print "Written by Ulrich Drepper <drepper\@gnu.org>\n";

        exit 0;
    } elsif ($ARGV[0] eq "--h" || $ARGV[0] eq "--he" || $ARGV[0] eq "--hel" ||
             $ARGV[0] eq "--help") {
        &usage;
    } elsif ($ARGV[0] =~ /^-/) {
        print "$progname: unrecognized option `$ARGV[0]'\n";
        print "Try `$progname --help' for more information.\n";
        exit 1;
    } else {
        last arglist;
    }
}

if ($#ARGV == 0) {
    $binary="";
    $data=$ARGV[0];
} elsif ($#ARGV == 1) {
    $binary=$ARGV[0];
    $data=$ARGV[1];

    if ($binary =~ /^.*[\/].*$/) {
        $prog = $binary;
    } else {
        $prog = "./$binary";
    }
    # Set the environment variable LD_TRACE_LOADED_OBJECTS to 2 so the
    # executable is also printed.
    if (open (locs, "env LD_TRACE_LOADED_OBJECTS=2 $prog |")) {
        while (<locs>) {
            chop;
            if (/^.*=> (.*) .(0x[0123456789abcdef]*).$/) {
                $locs{$1} = $2;
                $rel{$1} = hex($2);
            }
        }
        close (LOCS);
    }
} else {
    die "Wrong number of arguments, run $progname --help for help.";
}

sub addr2line {
    my $addr = pop(@_);
    my $prog = pop(@_);
    if (open (ADDR, "addr2line -e $prog $addr|")) {
        my $line = <ADDR>;
        chomp $line;
        close (ADDR);
        if ($line ne '??:0') {
            return $line
        }
    }
}
sub location {
    my $str = pop(@_);
    return $str if ($str eq "");
    if ($str =~ /.*[[](0x[^]]*)]:(.)*/) {
        my $addr = $1;
        my $fct = $2;
        return $cache{$addr} if (exists $cache{$addr});
        if ($binary ne "") {
            my $line = &addr2line($binary, $addr);
            if ($line) {
                $cache{$addr} = $line;
                return $cache{$addr};
            }
        }
        $cache{$addr} = $str = "$fct @ $addr";
    } elsif ($str =~ /^(.*):.*[[](0x[^]]*)]$/) {
        my $prog = $1;
        my $addr = $2;
        my $searchaddr;
        return $cache{$addr} if (exists $cache{$addr});
        $searchaddr = sprintf "%#x", hex($addr) + $rel{$prog};
        if ($binary ne "") {
            for my $address ($searchaddr, $addr) {
                my $line = &addr2line($prog, $address);
                if ($line) {
                    $cache{$addr} = $line;
                    return $cache{$addr};
                }
            }
        }
        $cache{$addr} = $str = $addr;
    } elsif ($str =~ /^.*[[](0x[^]]*)]$/) {
        my $addr = $1;
        return $cache{$addr} if (exists $cache{$addr});
        if ($binary ne "") {
            my $line = &addr2line($binary, $addr);
            if ($line) {
                $cache{$addr} = $line;
                return $cache{$addr};
            }
        }
        $cache{$addr} = $str = $addr;
    }
    return $str;
}

# When no explicit binary was provided, attempt to extract the binary / library
# path from a caller token like: /lib/libc.so.6:(__strdup+20)[0x9191c]
# Returns just the basename (e.g., libc.so.6) or empty string if not parsable
sub binname {
        my $s = shift;
        return '' if ($binary ne '');
        return '' if (!defined $s || $s eq '');
        # Accept patterns:
        #  /path/lib.so:(func+off)[0xADDR]
        #  /path/lib.so:[0xADDR]
        #  /deep/dir/bin_name:(...)
        if ($s =~ m{^(/[^:]+):}) {
                my $path = $1;
                $path =~ s{.*/}{}; # basename only
                return $path;
        }
        return '';
}

# Parse caller token to get "basename:0xADDR" when no explicit binary provided.
# Examples inputs:
#   /usr/lib/libc.so.6:(__strdup+20)[0x9191c]
#   /usr/lib/libev.so.4:[0x3704]
# Returns (basename, address_hex) or ('','') if not matched / binary given.
sub parse_caller {
        return ('','') if ($binary ne '');
        my $s = shift;
        return ('','') if (!defined $s || $s eq '');
        if ($s =~ m{^(/[^:]+):.*\[(0x[0-9a-fA-F]+)\]$}) {
                my ($path,$addr) = ($1,$2);
                $path =~ s{.*/}{}; # basename
                return ($path,$addr);
        }
        if ($s =~ m{^(/[^:]+):\[(0x[0-9a-fA-F]+)\]$}) {
                my ($path,$addr) = ($1,$2);
                $path =~ s{.*/}{};
                return ($path,$addr);
        }
        return ('','');
}

# Produce a canonical caller string like "libc.so.6:0x9191c" when possible.
# Falls back to bin name alone or original location() output.
sub canonical_caller {
        my $raw = shift;
        return '' if (!defined $raw || $raw eq '');
        my ($pbin,$paddr) = &parse_caller($raw);
        if ($pbin ne '' && $paddr ne '') {
                return "$pbin:$paddr";
        }
        my $bin = &binname($raw);
        if ($bin ne '') {
                # Try to extract address from raw if present
                if ($raw =~ /(0x[0-9a-fA-F]+)/) {
                        return "$bin:$1";
                }
                return $bin;
        }
        # Last resort: resolved location or raw
        my $loc = &location($raw);
        # Convert pattern "func @ 0xADDR" to "func:0xADDR" for consistency
        if ($loc =~ /^(.*) \@ (0x[0-9a-fA-F]+)$/) {
                return "$1:$2";
        }
        return $loc;
}

# Tracking hashes for statistics
my %dup_count;         # alloc address -> duplicate attempt count
my %dup_size_sum;      # alloc address -> cumulative duplicate requested size
my %dup_first_where;   # alloc address -> first caller location seen for duplicate
my %free_never_count;  # address -> times freed without prior allocation
my %free_never_where;  # address -> first location where invalid free observed

$nr=0;
open(DATA, "<$data") || die "Cannot open mtrace data file";
while (<DATA>) {
    my @cols = split (' ');
    my $n, $where;
    if ($cols[0] eq "@") {
        # We have address and/or function name.
        $where=$cols[1];
        $n=2;
    } else {
        $where="";
        $n=0;
    }

    $allocaddr=$cols[$n + 1];
    $howmuch=hex($cols[$n + 2]);

    ++$nr;
    SWITCH: {
                if ($cols[$n] eq "+") {
                    if (defined $allocated{$allocaddr}) {
                        # Duplicate allocation attempt of an already allocated pointer.
                        my $orig = &canonical_caller($addrwas{$allocaddr});
                        $orig = "at $orig" if ($orig ne '' && $orig !~ /^at /);
                        printf ("+ %#018x Alloc %d duplicate: %s %s\n",
                                hex($allocaddr), $howmuch, $orig, $where);
                        $dup_count{$allocaddr}++;
                        $dup_size_sum{$allocaddr} += $howmuch;
                        $dup_first_where{$allocaddr} //= &canonical_caller($addrwas{$allocaddr});
                    } elsif ($allocaddr =~ /^0x/) {
                        $allocated{$allocaddr}=$howmuch;
                        $addrwas{$allocaddr}=$where;
                    }
                    last SWITCH;
                }
        if ($cols[$n] eq "-") {
            if (defined $allocated{$allocaddr}) {
                undef $allocated{$allocaddr};
                undef $addrwas{$allocaddr};
            } else {
                my $loc_print = &location($where);
                printf ("- %#018x Free %d was never alloc'd %s\n",
                        hex($allocaddr), $nr, $loc_print);
                $free_never_count{$allocaddr}++;
                # Keep the raw token (not location-resolved) for better canonical parsing later.
                if (!exists $free_never_where{$allocaddr} && defined $where && $where ne '') {
                    $free_never_where{$allocaddr} = $where;
                } elsif (!exists $free_never_where{$allocaddr}) {
                    # Fall back to the printable location if raw is unavailable.
                    $free_never_where{$allocaddr} = $loc_print;
                }
            }
            last SWITCH;
        }
        if ($cols[$n] eq "<") {
            if (defined $allocated{$allocaddr}) {
                undef $allocated{$allocaddr};
                undef $addrwas{$allocaddr};
            } else {
                my $loc_print = &location($where);
                printf ("- %#018x Realloc %d was never alloc'd %s\n",
                        hex($allocaddr), $nr, $loc_print);
                # Not tracked in free_never_* stats currently, but could be if desired.
            }
            last SWITCH;
        }
        if ($cols[$n] eq ">") {
            if (defined $allocated{$allocaddr}) {
                printf ("+ %#018x Realloc %d duplicate: %#010x %s %s\n",
                        hex($allocaddr), $nr, $allocated{$allocaddr},
                        &location($addrwas{$allocaddr}), &location($where));
            } else {
                $allocated{$allocaddr}=$howmuch;
                $addrwas{$allocaddr}=$where;
            }
            last SWITCH;
        }
        if ($cols[$n] eq "=") {
            # Ignore "= Start".
            last SWITCH;
        }
        if ($cols[$n] eq "!") {
            # Ignore failed realloc for now.
            last SWITCH;
        }
    }
}
close (DATA);

# Now print all remaining entries.
@addrs= keys %allocated;
$anything=0;
if ($#addrs >= 0) {
    foreach $addr (sort @addrs) {
        if (defined $allocated{$addr}) {
            if ($anything == 0) {
                print "\nMemory not freed:\n-----------------\n";
                print ' ' x (18 - 7), "Address     Size     Caller\n";
                $anything=1;
            }
            my ($pbin,$paddr) = &parse_caller($addrwas{$addr});
            if ($pbin ne '' && $paddr ne '') {
                printf ("%#018x %#8x  at %s:%s\n", hex($addr), $allocated{$addr}, $pbin, $paddr);
            } else {
                my $bin = &binname($addrwas{$addr});
                if ($bin ne '') {
                    printf ("%#018x %#8x  at %s\n", hex($addr), $allocated{$addr}, $bin);
                } else {
                    my $loc = &location($addrwas{$addr});
                    printf ("%#018x %#8x  at %s\n", hex($addr), $allocated{$addr}, $loc);
                }
            }
        }
    }
}
print "No memory leaks.\n" if ($anything == 0);

# Duplicate allocation summary
if (%dup_count) {
        print "\nDuplicate Allocation Summary:\n----------------------------\n";
        printf "%18s %10s %14s  %s\n", 'Address', 'Count', 'TotalBytes', 'Original Caller';
        foreach my $addr (sort { $dup_size_sum{$b} <=> $dup_size_sum{$a} } keys %dup_count) {
                my $cc = $dup_first_where{$addr};
                $cc = &canonical_caller($cc) if ($cc ne '');
                printf "%#018x %10d %14d  %s\n", hex($addr), $dup_count{$addr}, $dup_size_sum{$addr}, ($cc // '');
        }
}

# Invalid free summary
if (%free_never_count) {
        print "\nInvalid Free Summary (Freed Without Alloc):\n------------------------------------------\n";
        printf "%18s %10s  %s\n", 'Address', 'Count', 'First Seen At';
        foreach my $addr (sort { $free_never_count{$b} <=> $free_never_count{$a} } keys %free_never_count) {
                my $cc = $free_never_where{$addr};
                $cc = &canonical_caller($cc) if ($cc ne '');
                printf "%#018x %10d  %s\n", hex($addr), $free_never_count{$addr}, ($cc // '');
        }
}

