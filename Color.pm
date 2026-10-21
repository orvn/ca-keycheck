package Color;
# optional ANSI color for check.pl, which falls back to plain text without this file

use strict;
use warnings;
use Term::ANSIColor qw(colored);
use Exporter 'import';
our @EXPORT = qw(paint paint_err);

# color only on a terminal, and honor NO_COLOR (https://no-color.org)
my %use_color = (
    out => -t STDOUT && !defined $ENV{NO_COLOR},
    err => -t STDERR && !defined $ENV{NO_COLOR},
);

sub paint     { my ($style, $txt) = @_; $use_color{out} ? colored($txt, $style) : $txt }
sub paint_err { my ($style, $txt) = @_; $use_color{err} ? colored($txt, $style) : $txt }

1;
