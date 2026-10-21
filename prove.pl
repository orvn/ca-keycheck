#!/usr/bin/env perl
# reproduce the disclosure's proof-of-possession for a recovered small-scalar key
#
# for each compromised cert in a file, check.pl recovers the scalar, then this
# rebuilds the private key from it, signs a message, and verifies the signature
# against the cert's own public key. a good verify proves the recovered key is real
#
# this signs only a short message (default below); it never builds a certificate
# https://web.archive.org/web/20261020211414/https://emudhra.we-have-a-problem.com/

use strict;
use warnings;
use MIME::Base64 qw(encode_base64);
use File::Temp qw(tempdir);
use FindBin;
use lib $FindBin::Bin;

# color comes from Color.pm next to this script; without it, output is plain text
BEGIN {
    unless (eval { require Color; Color->import; 1 }) {
        no warnings 'once';
        *paint = sub { $_[1] };
    }
}

# per-curve: coordinate bytes, digest, and the named-curve OID (DER contents)
my %curve = (
    'P-384' => { len => 48, md => 'sha384', oid => "\x2b\x81\x04\x00\x22" },
    'P-256' => { len => 32, md => 'sha256', oid => "\x2a\x86\x48\xce\x3d\x03\x01\x07" },
);

# ---- minimal DER helpers ----
sub der_len {
    my $n = shift;
    return pack('C', $n) if $n < 0x80;
    my $b = '';
    while ($n) { $b = pack('C', $n & 0xff) . $b; $n >>= 8 }
    return pack('C', 0x80 | length $b) . $b;
}
sub tlv { my ($tag, $v) = @_; pack('C', $tag) . der_len(length $v) . $v }

# ---- build a SEC1 "EC PRIVATE KEY" PEM from a scalar (RFC 5915) ----
sub key_pem {
    my ($scalar, $cv) = @_;
    my $raw    = pack 'H*', sprintf('%0*x', 2 * $cv->{len}, $scalar);
    my $der    = tlv(0x30,
                     tlv(0x02, "\x01")                  # version 1
                   . tlv(0x04, $raw)                    # privateKey (scalar)
                   . tlv(0xa0, tlv(0x06, $cv->{oid}))); # [0] named curve
    my $b64 = encode_base64($der, '');
    $b64 =~ s/(.{64})/$1\n/g;
    $b64 =~ s/\n?$/\n/;
    return "-----BEGIN EC PRIVATE KEY-----\n$b64-----END EC PRIVATE KEY-----\n";
}

sub write_file { my ($path, $data) = @_; open my $fh, '>', $path or die "$path: $!\n"; print $fh $data; close $fh }
sub slurp      { my ($path) = @_; open my $fh, '<', $path or return ''; local $/; <$fh> }

my ($file, $msg) = @ARGV;
die "usage: $0 cert_or_chain.pem [message]\n" unless $file && -f $file;
$msg //= 'We have a problem here';

my $certs = slurp($file);
my @certs = $certs =~ /(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)/gs;
die "no certificates in $file\n" unless @certs;

my $dir = tempdir(CLEANUP => 1);
write_file("$dir/msg.txt", $msg);
print "message: ", paint('bold', $msg), "\n";

my $proven = 0;
for my $cert (@certs) {
    write_file("$dir/cert.pem", $cert);

    # let check.pl do the recovery, and read back the curve and scalar
    my $out = qx($^X "$FindBin::Bin/check.pl" "$dir/cert.pem" 2>/dev/null);
    next unless $out =~ /(P-\d+)\s+COMPROMISED\s+private scalar = (\d+)/;
    my ($cname, $scalar) = ($1, $2);
    my $cv = $curve{$cname} or next;

    my ($subj) = qx(openssl x509 -in "$dir/cert.pem" -noout -subject -nameopt multiline 2>/dev/null) =~ /commonName\s*=\s*(.+)/;
    $subj //= '?';
    printf "\n%s  (%s, scalar %d)\n", paint('cyan', $subj), $cname, $scalar;

    # rebuild the key, and confirm its public point matches the cert's
    write_file("$dir/key.pem", key_pem($scalar, $cv));
    my $pub_from_key  = qx(openssl pkey -in "$dir/key.pem" -pubout 2>/dev/null);
    my $pub_from_cert = qx(openssl x509 -in "$dir/cert.pem" -noout -pubkey 2>/dev/null);
    write_file("$dir/certpub.pem", $pub_from_cert);

    if ($pub_from_key && $pub_from_key eq $pub_from_cert) {
        print "  ", paint('green', 'public key matches the certificate'), "\n";
    } else {
        print "  ", paint('bold red', 'public key does NOT match'), " (skipping)\n";
        next;
    }

    # sign the message with the rebuilt key, then verify against the cert's pubkey
    system("openssl dgst -$cv->{md} -sign '$dir/key.pem' -out '$dir/sig' '$dir/msg.txt' 2>/dev/null") == 0
        or do { print "  ", paint('bold red', 'signing failed'), "\n"; next };
    my $v = qx(openssl dgst -$cv->{md} -verify "$dir/certpub.pem" -signature "$dir/sig" "$dir/msg.txt" 2>&1);
    if ($v =~ /Verified OK/) {
        print "  ", paint('bold green', 'signature verifies against the cert pubkey  (key is real)'), "\n";
        $proven++;
    } else {
        chomp $v;
        print "  ", paint('bold red', "verify failed: $v"), "\n";
    }
}

print "\n", paint('bold', "$proven key(s) proven\n");
exit($proven ? 0 : 1);
