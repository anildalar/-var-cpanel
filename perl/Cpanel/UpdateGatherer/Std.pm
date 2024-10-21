package Cpanel::UpdateGatherer::Std;

# cpanel - Cpanel/UpdateGatherer/Std.pm            Copyright 2022 cPanel, L.L.C.
#                                                           All rights reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

use strict;
use warnings;

=pod

common::sense like for UpdateGaterer.

    use Cpanel::UpdateGatherer::Std;

This is importing the following to your namespace
similar to Cpanel::UpdateGatherer::Std. common::sense like for
UpdateGatherer.

    use strict;
    use warnings;

    use v5.26;

    use feature 'signatures';
    no warnings 'experimental::signatures';

=cut

sub import {

    # auto import strict and warnings to our caller
    warnings->import();
    strict->import();

    # Gatherer package was introduced in 11.72 and is designed to work with Perl 5.26+
    require feature;
    feature->import( ':5.26', 'signatures' );

    if ( $] < 5.035 ) {
        warnings->unimport('experimental::signatures');
    }

    return;
}

1;
