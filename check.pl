#!/usr/bin/env perl
# small-scalar check for the eMudhra P-384 intermediates
# https://web.archive.org/web/20261020211414/https://emudhra.we-have-a-problem.com/
#
# confirms the published claim: each private key is a tiny integer (1-255)
# method: derive k*G for every k in that range and compare to the cert's public point
# this only READS public keys

use strict;
use warnings;
use Math::BigInt;
use IPC::Open2;

# ---- P-384 (secp384r1) domain parameters, public NIST constants ----
my $p  = Math::BigInt->from_hex('fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff');
my $a  = $p->copy->bsub(3);                 # a = p - 3 for the NIST prime curves
my $b  = Math::BigInt->from_hex('b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef');
my $Gx = Math::BigInt->from_hex('aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7');
my $Gy = Math::BigInt->from_hex('3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f');

# a point is [x, y] as BigInts, or undef for the point at infinity (identity)
my $G = [$Gx, $Gy];

# modular reduce helper, keeps everything in [0, p)
sub m_ { my $v = shift; $v->copy->bmod($p) }

# affine point addition over F_p, handles doubling and the identity
sub padd {
    my ($P, $Q) = @_;
    return $Q unless defined $P;             # O + Q = Q
    return $P unless defined $Q;             # P + O = P
    my ($x1, $y1) = @$P;
    my ($x2, $y2) = @$Q;

    my $lambda;
    if ($x1->bcmp($x2) == 0) {
        # same x: either doubling, or P + (-P) = O
        return undef if $y1->bcmp($y2) != 0 || $y1->is_zero;
        # lambda = (3*x1^2 + a) / (2*y1)
        my $num = m_($x1->copy->bmul($x1)->bmul(3)->badd($a));
        my $den = m_($y1->copy->bmul(2))->bmodinv($p);
        $lambda = m_($num->bmul($den));
    } else {
        # lambda = (y2 - y1) / (x2 - x1)
        my $num = m_($y2->copy->bsub($y1));
        my $den = m_($x2->copy->bsub($x1))->bmodinv($p);
        $lambda = m_($num->bmul($den));
    }

    # x3 = lambda^2 - x1 - x2 ; y3 = lambda*(x1 - x3) - y1
    my $x3 = m_($lambda->copy->bmul($lambda)->bsub($x1)->bsub($x2));
    my $y3 = m_($lambda->copy->bmul($x1->copy->bsub($x3))->bsub($y1));
    return [$x3, $y3];
}

# curve membership test: y^2 == x^3 + a*x + b (mod p)
sub on_curve {
    my ($P) = @_;
    return 1 unless defined $P;              # identity is on the curve by convention
    my ($x, $y) = @$P;
    my $lhs = m_($y->copy->bmul($y));
    my $rhs = m_($x->copy->bmul($x)->bmul($x)
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
# returns [x, y] BigInts from the 0x04 || X || Y encoding (97 bytes for P-384)
sub point_from_cert {
    my ($cert) = @_;
    my $txt = openssl_in('openssl x509 -noout -pubkey 2>/dev/null | openssl pkey -pubin -text -noout 2>/dev/null', $cert);
    die "openssl could not read cert\n" unless $txt;

    # scrape the hex bytes under the "pub:" block
    my ($blk) = $txt =~ /pub:\s*\n(.*?)(?:ASN1 OID|NIST CURVE|\z)/s;
    die "no public point found\n" unless $blk;
    (my $hex = $blk) =~ s/[^0-9a-f]//g;      # drop colons, whitespace, indentation

    die "not P-384 (unexpected point length)\n" unless length($hex) == 2 * 97;
    die "not an uncompressed point\n" unless substr($hex, 0, 2) eq '04';
    my $x = Math::BigInt->from_hex(substr($hex, 2,  96));
    my $y = Math::BigInt->from_hex(substr($hex, 98, 96));
    return [$x, $y];
}

# ---- build k*G for k = 1..255 once, reused across all certs ----
# accumulate by repeated addition of G, cheap at this range
sub small_multiples {
    my ($max) = @_;
    my @mult;                                # $mult[$k] = k*G
    my $acc;                                 # starts at identity (undef)
    for my $k (1 .. $max) {
        $acc = padd($acc, $G);
        $mult[$k] = $acc;
    }
    return @mult;
}

# ---- self-test: prove the math is right before trusting a match ----
sub selftest {
    die "base point G is not on the curve\n" unless on_curve($G);
    my @mult = small_multiples(255);
    for my $k (1 .. 255) {
        die "computed ${k}*G is off-curve\n" unless on_curve($mult[$k]);
    }
    printf "selftest ok: G and all of 1*G..255*G lie on P-384\n";
    printf "  4*G.x = %s\n", $mult[4][0]->to_hex;   # the OV G3C scalar, per the report
    return @mult;
}

# ---- main ----
my @mult = selftest();

unless (@ARGV) {
    print "\nusage: $0 cert1.pem [cert2.pem ...]\n";
    print "every cert in each file (chains included) is checked against 1*G..255*G\n";
    exit 0;
}

for my $pem (@ARGV) {
    my @certs = eval { certs_from_file($pem) };
    unless (@certs) {
        warn "skipping: $@";
        next;
    }
    print "\n$pem\n";
    for my $i (0 .. $#certs) {
        my $label = sprintf "  [%d] %s", $i + 1, cn_of($certs[$i]);
        my $target = eval { point_from_cert($certs[$i]) };
        unless ($target) {
            printf "%-50s skipped: %s", $label, $@;
            next;
        }
        my $found;
        for my $k (1 .. 255) {
            if ($mult[$k][0]->bcmp($target->[0]) == 0
             && $mult[$k][1]->bcmp($target->[1]) == 0) {
                $found = $k;
                last;
            }
        }
        if (defined $found) {
            printf "%-50s COMPROMISED  private scalar = %d\n", $label, $found;
        } else {
            printf "%-50s no small scalar <= 255\n", $label;
        }
    }
}
