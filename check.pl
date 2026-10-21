#!/usr/bin/env perl
# small-scalar check for the eMudhra P-384 intermediates (P-256 keys, e.g. leaves, too)
# https://web.archive.org/web/20261020211414/https://emudhra.we-have-a-problem.com/
#
# confirms the published claim: each private key is a tiny integer (1-255)
# method: derive k*G for every k in that range and compare to the cert's public point
# this only READS public keys

use strict;
use warnings;
use Math::BigInt;
use IPC::Open2;
use FindBin;
use lib $FindBin::Bin;

# color comes from Color.pm next to this script; without it, output is plain text
BEGIN {
    unless (eval { require Color; Color->import; 1 }) {
        no warnings 'once';
        *paint = *paint_err = sub { $_[1] };
    }
}

# full private key as colon-separated bytes, $len bytes, 16 per line
# leading zero bytes are dimmed so the tiny value stands out
sub key_lines {
    my ($k, $len) = @_;
    my @bytes = unpack '(A2)*', sprintf('%0*x', 2 * $len, $k);
    my @lines;
    while (my @row = splice @bytes, 0, 16) {
        push @lines, join ':', map { $_ eq '00' ? paint('faint', $_) : paint('bold red', $_) } @row;
    }
    return @lines;
}

# ---- domain parameters, public NIST constants, keyed by openssl's ASN1 OID name ----
# a = p - 3 for the NIST prime curves; len = bytes per coordinate
sub curve {
    my ($name, $len, $p, $b, $Gx, $Gy) = @_;
    $p = Math::BigInt->from_hex($p);
    return {
        name => $name,
        len  => $len,
        p    => $p,
        a    => $p->copy->bsub(3),
        b    => Math::BigInt->from_hex($b),
        G    => [Math::BigInt->from_hex($Gx), Math::BigInt->from_hex($Gy)],
    };
}

my %curves = (
    secp384r1 => curve('P-384', 48,
        'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff',
        'b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef',
        'aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7',
        '3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f'),
    prime256v1 => curve('P-256', 32,
        'ffffffff00000001000000000000000000000000ffffffffffffffffffffffff',
        '5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b',
        '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296',
        '4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5'),
);

# a point is [x, y] as BigInts, or undef for the point at infinity (identity)

# modular reduce helper, keeps everything in [0, p)
sub m_ { my ($c, $v) = @_; $v->copy->bmod($c->{p}) }

# affine point addition over F_p, handles doubling and the identity
sub padd {
    my ($c, $P, $Q) = @_;
    my ($p, $a) = @$c{qw(p a)};
    return $Q unless defined $P;             # O + Q = Q
    return $P unless defined $Q;             # P + O = P
    my ($x1, $y1) = @$P;
    my ($x2, $y2) = @$Q;

    my $lambda;
    if ($x1->bcmp($x2) == 0) {
        # same x: either doubling, or P + (-P) = O
        return undef if $y1->bcmp($y2) != 0 || $y1->is_zero;
        # lambda = (3*x1^2 + a) / (2*y1)
        my $num = m_($c, $x1->copy->bmul($x1)->bmul(3)->badd($a));
        my $den = m_($c, $y1->copy->bmul(2))->bmodinv($p);
        $lambda = m_($c, $num->bmul($den));
    } else {
        # lambda = (y2 - y1) / (x2 - x1)
        my $num = m_($c, $y2->copy->bsub($y1));
        my $den = m_($c, $x2->copy->bsub($x1))->bmodinv($p);
        $lambda = m_($c, $num->bmul($den));
    }

    # x3 = lambda^2 - x1 - x2 ; y3 = lambda*(x1 - x3) - y1
    my $x3 = m_($c, $lambda->copy->bmul($lambda)->bsub($x1)->bsub($x2));
    my $y3 = m_($c, $lambda->copy->bmul($x1->copy->bsub($x3))->bsub($y1));
    return [$x3, $y3];
}

# curve membership test: y^2 == x^3 + a*x + b (mod p)
sub on_curve {
    my ($c, $P) = @_;
    return 1 unless defined $P;              # identity is on the curve by convention
    my ($x, $y) = @$P;
    my ($a, $b) = @$c{qw(a b)};
    my $lhs = m_($c, $y->copy->bmul($y));
    my $rhs = m_($c, $x->copy->bmul($x)->bmul($x)
                   ->badd($a->copy->bmul($x))->badd($b));
    return $lhs->bcmp($rhs) == 0;
}

# ---- split a PEM file into its certificates (a chain file holds several) ----
sub certs_from_file {
    my ($path) = @_;
    open my $fh, '<', $path or die "cannot open $path: $!\n";
    my $data = do { local $/; <$fh> };
    my @certs = $data =~ /(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)/gs;
    die "no certificates in $path\n" unless @certs;
    return @certs;
}

# run a shell pipeline with $input on stdin, return its stdout
sub openssl_in {
    my ($cmd, $input) = @_;
    my $pid = open2(my $out, my $in, $cmd);
    print $in $input;
    close $in;
    my $txt = do { local $/; <$out> };
    waitpid $pid, 0;
    return $txt // '';
}

sub cn_of {
    my ($cert) = @_;
    my $subj = openssl_in('openssl x509 -noout -subject -nameopt multiline 2>/dev/null', $cert);
    my ($cn) = $subj =~ /commonName\s*=\s*(.+)/;
    return $cn // '?';
}

# ---- pull the uncompressed public point out of a cert via openssl ----
# returns (curve, [x, y]) from the 0x04 || X || Y encoding (1 + 2*len bytes)
sub point_from_cert {
    my ($cert) = @_;
    my $txt = openssl_in('openssl x509 -noout -pubkey 2>/dev/null | openssl pkey -pubin -text -noout 2>/dev/null', $cert);
    die "openssl could not read cert\n" unless $txt;

    my ($oid) = $txt =~ /ASN1 OID:\s*(\S+)/;
    die "not an EC key\n" unless $oid;
    my $c = $curves{$oid} or die "unsupported curve $oid\n";

    # scrape the hex bytes under the "pub:" block
    my ($blk) = $txt =~ /pub:\s*\n(.*?)(?:ASN1 OID|NIST CURVE|\z)/s;
    die "no public point found\n" unless $blk;
    (my $hex = $blk) =~ s/[^0-9a-f]//g;      # drop colons, whitespace, indentation

    my $n = 2 * $c->{len};                   # hex chars per coordinate
    die "unexpected point length for $c->{name}\n" unless length($hex) == 2 + 2 * $n;
    die "not an uncompressed point\n" unless substr($hex, 0, 2) eq '04';
    my $x = Math::BigInt->from_hex(substr($hex, 2,      $n));
    my $y = Math::BigInt->from_hex(substr($hex, 2 + $n, $n));
    return ($c, [$x, $y]);
}

# ---- build k*G for k = 1..255 once, reused across all certs ----
# accumulate by repeated addition of G, cheap at this range
sub small_multiples {
    my ($c, $max) = @_;
    my @mult;                                # $mult[$k] = k*G
    my $acc;                                 # starts at identity (undef)
    for my $k (1 .. $max) {
        $acc = padd($c, $acc, $c->{G});
        $mult[$k] = $acc;
    }
    return \@mult;
}

# ---- self-test: prove the math is right before trusting a match ----
sub selftest {
    my ($c) = @_;
    die "$c->{name}: base point G is not on the curve\n" unless on_curve($c, $c->{G});
    my $mult = small_multiples($c, 255);
    for my $k (1 .. 255) {
        die "$c->{name}: computed ${k}*G is off-curve\n" unless on_curve($c, $mult->[$k]);
    }
    printf "%s G and all of 1*G..255*G lie on %s\n", paint('green', 'selftest ok:'), $c->{name};
    printf "  4*G.x = %s\n", $mult->[4][0]->to_hex;
    $c->{mult} = $mult;
}

# ---- main ----
selftest($curves{$_}) for qw(secp384r1 prime256v1);

unless (@ARGV) {
    print "\nusage: $0 cert1.pem [cert2.pem ...]\n";
    print "every cert in each file (chains included) is checked against 1*G..255*G\n";
    exit 0;
}

for my $pem (@ARGV) {
    my @certs = eval { certs_from_file($pem) };
    unless (@certs) {
        warn paint_err('yellow', 'skipping:') . " $@";
        next;
    }
    print "\n", paint('bold', $pem), "\n";
    for my $i (0 .. $#certs) {
        my $label = sprintf "  [%d] %s", $i + 1, cn_of($certs[$i]);
        my ($c, $target) = eval { point_from_cert($certs[$i]) };
        unless ($target) {
            printf "%-50s %s %s", $label, paint('yellow', 'skipped:'), $@;
            next;
        }
        my $mult = $c->{mult};
        my $found;
        for my $k (1 .. 255) {
            if ($mult->[$k][0]->bcmp($target->[0]) == 0
             && $mult->[$k][1]->bcmp($target->[1]) == 0) {
                $found = $k;
                last;
            }
        }
        if (defined $found) {
            printf "%-50s %s  %s  private scalar = %d\n", $label, paint('cyan', $c->{name}),
                paint('bold red', 'COMPROMISED'), $found;
            printf "      private key (%d bytes):\n", $c->{len};
            print "        $_\n" for key_lines($found, $c->{len});
        } else {
            printf "%-50s %s  %s\n", $label, paint('cyan', $c->{name}), paint('green', 'no small scalar <= 255');
        }
    }
}
