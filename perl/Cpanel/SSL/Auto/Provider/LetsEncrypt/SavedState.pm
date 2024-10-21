package Cpanel::SSL::Auto::Provider::LetsEncrypt::SavedState;

# cpanel - Cpanel/SSL/Auto/Provider/LetsEncrypt/SavedState.pm
#                                               Copyright(c) 2019 cPanel, L.L.C.
#                                                           All rights reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

use strict;
use warnings;

use feature qw(signatures);
no warnings 'experimental::signatures';    ## no critic qw(Warn)

=encoding utf-8

=head1 NAME

Cpanel::SSL::Auto::Provider::LetsEncrypt::SavedState

=head1 DESCRIPTION

Let’s Encrypt’s implementation of the IETF’s ACME standard (RFC 8555)
imposes a rate limit of 300 certificate orders per 3-hour period.
This rate limit (new in this version of Let’s Encrypt’s API) needs to be
handled differently from all of LE’s other rate limits because the
rate limit on orders affects all interaction with Let’s Encrypt; thus,
when we see that specific rate limit, we need to stop what AutoSSL is
doing and resume later.

This class facilitates that by providing the means to save the
Let’s Encrypt provider’s state and to resume that state the next time
AutoSSL runs.

=cut

#----------------------------------------------------------------------

use Try::Tiny;

use DBI;
use DBD::SQLite;

our $_DBFILE = '/var/cpanel/letsencrypt-v2-dcvcache.sqlite';

our $SCHEMA_VERSION = 1;

#----------------------------------------------------------------------

=head1 METHODS

=head2 $obj = I<CLASS>->new( $ACCOUNT_ID )

Creates an instance of this class. $ACCOUNT_ID is as Let’s Encrypt
returns on account creation.

=cut

sub new ( $class, $account_id ) {    ## no critic qw(Proto)
    my $dbh = _get_dbh();

    $dbh->{'RaiseError'} = 1;

    my %self_h = ( _db => $dbh );
    my $self = bless \%self_h, $class;

    $self->_ensure_schema($account_id);

    return $self;
}

# Stubbed out in tests.
sub _get_dbh {
    my $dbh = DBI->connect( "dbi:SQLite:dbname=$_DBFILE", "", "" ) || do {
        die "SQLite open($_DBFILE): $DBI::err ($DBI::state) - $DBI::errstr";
    };

    die "“$_DBFILE” opened read-only!" if $dbh->{'ReadOnly'};

    return $dbh;
}

#----------------------------------------------------------------------

=head2 $num = I<OBJ>->count_domains()

Returns a count of every domain whose DCV info is recorded.

=cut

sub count_domains($self) {
    return ( $self->{'_db'}->selectrow_array('SELECT COUNT(*) FROM (SELECT domain FROM successes UNION SELECT domain FROM http_errors UNION SELECT domain FROM dns_errors)') )[0];
}

#----------------------------------------------------------------------

=head2 $domains_ar = I<OBJ>->get_domains_ar()

Returns a list of every domain whose DCV info is recorded.

=cut

sub get_domains_ar($self) {
    return $self->{'_db'}->selectcol_arrayref('SELECT domain FROM successes UNION SELECT domain FROM http_errors UNION SELECT domain FROM dns_errors');
}

#----------------------------------------------------------------------

=head2 ($success_expiry, $http_err, $dns_err) = I<OBJ>->get_domain_info( $DOMAIN )

The only returns should be:

=over

=item * expiry, undef, undef - DCV succeeded without incident.

=item * expiry, error, undef - HTTP DCV failed, but DNS succeeded.

=item * undef, error, error - HTTP & DNS DCV both failed.

=item * undef, undef, undef - No data for $DOMAIN.

=back

Note that the returned C<$success_expiry> may already be in the past,
or may be soon (even just a second or two into the future). The B<caller>
is expected to accommodate that scenario.

=cut

use constant _EXPIRY_PAD_TIME => 600;

sub get_domain_info ( $self, $domain ) {
    my ($expiry) = $self->{'_db'}->selectrow_array( 'SELECT expiry FROM successes WHERE domain=?', undef, $domain );

    my ($http) = $self->{'_db'}->selectrow_array( 'SELECT error FROM http_errors WHERE domain=?', undef, $domain );

    my ($dns) = $self->{'_db'}->selectrow_array( 'SELECT error FROM dns_errors WHERE domain=?', undef, $domain );

    return ( $expiry, $http, $dns );
}

# stubbed in tests
sub _time { return time }

#----------------------------------------------------------------------

=head2 I<OBJ>->set_success_expiry( $DOMAIN, $EXPIRY )

Sets the expiry time that Let’s Encrypt gave for $DOMAIN.

(NB: $EXPIRY should be in the format that RFC 3339 describes,
but this function doesn’t actually care.)

Returns I<OBJ>.

=cut

sub set_success_expiry ( $self, $domain, $expiry ) {
    _validate_rfc3339_or_die($expiry);

    return $self->_do_in_xaction(
        sub {
            my $dbh = shift;

            my ($http_err) = $dbh->selectrow_array( 'SELECT error from http_errors WHERE domain=?', undef, $domain );
            die "“$domain” already has an HTTP error!" if defined $http_err;

            my ($dns_err) = $dbh->selectrow_array( 'SELECT error from dns_errors WHERE domain=?', undef, $domain );
            die "“$domain” already has a DNS error!" if defined $dns_err;

            $dbh->do( "INSERT INTO successes (domain, expiry) VALUES (?, ?)", undef, $domain, $expiry );
        }
    );
}

sub _validate_rfc3339_or_die($str) {
    local ( $@, $! );
    require DateTime::Format::RFC3339;
    eval { DateTime::Format::RFC3339->new()->parse_datetime($str) } or do {
        die "Received invalid RFC 3339 date “$str”: $@";
    };
}

#----------------------------------------------------------------------

=head2 I<OBJ>->set_http_error( $DOMAIN, $ERROR )

Sets the description of the HTTP DCV failure.

Returns I<OBJ>.

=cut

sub set_http_error ( $self, $domain, $err ) {
    return $self->_set_error( $domain, 'http_errors', $err );
}

sub _set_error ( $self, $domain, $table, $err ) {
    return $self->_do_in_xaction(
        sub {
            my $dbh = shift();

            my ($expiry) = $dbh->selectrow_array( 'SELECT expiry FROM successes WHERE domain=?', undef, $domain );
            die "“$domain” already has a success!" if defined $expiry;

            $dbh->do( "REPLACE INTO $table (domain, error) VALUES (?, ?)", undef, $domain, $err );
        }
    );
}

#----------------------------------------------------------------------

=head2 I<OBJ>->set_dns_error( $DOMAIN, $ERROR )

Sets the description of the DNS DCV failure.

Returns I<OBJ>.

=cut

sub set_dns_error ( $self, $domain, $err ) {
    return $self->_set_error( $domain, 'dns_errors', $err );
}

#----------------------------------------------------------------------

=head2 I<OBJ>->purge_all()

Removes all domain info from the DB. Returns I<OBJ>.

=cut

sub purge_all($self) {
    return $self->_do_in_xaction(
        sub {
            my $dbh = shift();

            $dbh->do('DELETE FROM successes');
            $dbh->do('DELETE FROM http_errors');
            $dbh->do('DELETE FROM dns_errors');
        }
    );
}

# Useful enough to refactor and use elsewhere?
sub _do_in_xaction ( $self, $todo_cr ) {
    my $dbh = $self->{'_db'};

    $dbh->do('SAVEPOINT __general');

    try {
        $todo_cr->($dbh);
    }
    catch {
        my $err = $_;

        $dbh->do('ROLLBACK TO SAVEPOINT __general');

        local $@ = $err;
        die;
    }
    finally {
        $dbh->do('RELEASE SAVEPOINT __general');
    };

    return $self;
}

#----------------------------------------------------------------------

sub _ensure_schema ( $self, $account_id ) {    ## no critic qw(Proto)
    return $self->_do_in_xaction(
        sub {
            my $dbh = shift;

            $dbh->do('CREATE TABLE IF NOT EXISTS metadata (key text primary key, value text)');

            $dbh->do(
                q<
                    CREATE TABLE IF NOT EXISTS successes (
                        domain text not null primary key,
                        expiry text not null
                    )
                >
            );

            $dbh->do(
                q<
                    CREATE TABLE IF NOT EXISTS http_errors (
                        domain text not null primary key,
                        error text not null
                    )
                >
            );

            $dbh->do(
                q<
                    CREATE TABLE IF NOT EXISTS dns_errors (
                        domain text not null primary key,
                        error text not null
                    )
                >
            );

            $dbh->do( 'REPLACE INTO metadata (key, value) VALUES (?, ?)', undef, schema_version => $SCHEMA_VERSION );

            my ($saved_acct_id) = $dbh->selectrow_array( 'SELECT value FROM metadata WHERE key=?', undef, 'acme_account_id' );

            my $save_account_id_yn = 1;

            if ($saved_acct_id) {
                if ( $saved_acct_id eq $account_id ) {
                    $save_account_id_yn = 0;
                }
                else {
                    require Cpanel::Locale;

                    my $msg =
                      Cpanel::Locale->get_handle()->maketext( 'The current [asis,Let’s Encrypt] account ID ([_1]) differs from the one ([_2]) in the [asis,Let’s Encrypt] provider’s [asis,DCV] cache. The server is probably using a different [asis,Let’s Encrypt] account than it did when it last updated the [asis,DCV] cache. Purging cached [asis,DCV] data …', $account_id, $saved_acct_id );

                    warn "$msg\n";

                    $self->purge_all();
                }
            }

            if ($save_account_id_yn) {
                $dbh->do( 'REPLACE INTO metadata VALUES (?, ?)', undef, acme_account_id => $account_id );
            }
        }
    );

    return;
}

1;
