package Cpanel::UpdateGatherer::modules::VirtualUsers;

#                                      Copyright 2024 WebPros International, LLC
#                                                           All rights reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited.

use Cpanel::UpdateGatherer::Std;

use Cpanel::AccessIds       ();
use Cpanel::ConfigFiles     ();
use Cpanel::Config::Users   ();
use Cpanel::DateUtils       ();
use Cpanel::DBI::SQLite     ();
use Cpanel::Email::Accounts ();
use Cpanel::Exception       ();
use Cpanel::JSON            ();
use Cpanel::LoadFile        ();
use Cpanel::PwCache         ();
use Cpanel::SafeRun::Object ();

use Try::Tiny;

use File::ReadBackwards ();
use Time::Local         ();
use Time::Piece         ();

use Cpanel::UpdateGatherer::Std;    # restore features

=head1 NAME

Cpanel::UpdateGatherer::modules::VirtualUsers

=head1 SYNOPSIS

    use Cpanel::UpdateGatherer::modules::VirtualUsers ();

    my $meta = {};
    Cpanel::UpdateGatherer::modules::VirtualUsers->compile($meta);

=head1 DESCRIPTION

Module for collecting virtual user information from server.

=head1 RETURNS

If the function returns successfully, entry for virtual users should
have structure similar to

    {
        "accounts": {
            "cpanel": 19,
            "cpanel_recent_logins": 4,
            "cpanel_recent_impersonations": 7,
            "email": 10,
            "ftp": 9,
            "user_manager": 1,
            "webdisk": 7
        },
    }

=cut

sub compile ( $self, $meta ) {
    die 'Unable to parse meta variable' if !defined $meta;
    _add_virtual_users_to_metadata($meta);
    return 1;
}

sub _add_virtual_users_to_metadata ($meta) {
    my @users = _list_users();
    $meta->{'accounts'} = _count_all_users(@users);
    return;
}

sub _list_users {
    return Cpanel::Config::Users::getcpusers();
}

sub _count_all_users (@users) {
    my $tot_accounts = {
        'cpanel'                       => scalar @users,
        'cpanel_recent_logins'         => 0,
        'cpanel_recent_impersonations' => 0,
        'user_manager'                 => 0,
        'email'                        => 0,
        'ftp'                          => 0,
        'webdisk'                      => 0
    };

    for my $user (@users) {
        my $homedir = Cpanel::PwCache::gethomedir($user);

        Cpanel::AccessIds::ReducedPrivileges::call_as_user(
            sub {
                $tot_accounts->{'user_manager'} += _count_user_manager($homedir);
                $tot_accounts->{'email'}        += _count_email($user);
                $tot_accounts->{'ftp'}          += _count_ftp($homedir);
                $tot_accounts->{'webdisk'}      += _count_webdisk($homedir);
            },
            $user
        );
    }

    ( $tot_accounts->{'cpanel_recent_logins'}, $tot_accounts->{'cpanel_recent_impersonations'} ) = _count_recent_logins();

    return $tot_accounts;
}

sub _count_user_manager ($home) {

    # Using sqlite3 to load the file seemed to increase time taken by 1200+%
    my $db_file_contents = eval { Cpanel::LoadFile::load_if_exists( $home . '/.subaccounts/storage.sqlite' ) }
      or return 0;

    # Search and replace provides the number of occurences.
    my $count_users_type_sub = $db_file_contents =~ s/
            [a-z]           # last letter of lower case tld
            ([A-Z\d._-]+)   # get the capital username
            :[A-Z\d-]+      # capital domain
            .+              # several fields
            (sub(?i:\1))    # looking for 'sub' in front of lower_case(username) at end of line
         //xg;

    # There is an edge case where this is assigned an empty string which causes a warning when we later do arithmetic.
    # This ternary ensures it's not empty and therefore no warning is thrown.
    return $count_users_type_sub ? $count_users_type_sub : 0;
}

sub _count_email ($user) {
    return eval {
        my ( $popaccts_ref, $_manage_err ) = Cpanel::Email::Accounts::manage_email_accounts_db(
            'event'   => 'fetch',
            'no_disk' => 1,
        );

        my $n;
        for my $domain ( sort keys %$popaccts_ref ) {
            $n += $popaccts_ref->{$domain}{account_count};    # alternatively, this count can be grabbed from the table of accounts returned in $popaccts_ref->{$domain}{accounts}
        }
        $n;
    } // 0;
}

sub _count_ftp ($home) {
    my $ftp_file = $home . '/.cpanel/datastore/ftp_LISTSTORE';
    return 0 unless -f $ftp_file && -s _;

    my $ret;
    try {
        my $ftplist_store = Cpanel::JSON::LoadFile($ftp_file);
        $ret = scalar( grep { $_->{'type'} eq 'sub' } @{ $ftplist_store->{'data'} } );
    };

    return $ret // 0;
}

sub _count_webdisk ($home) {
    my $content = eval { Cpanel::LoadFile::load_if_exists( $home . '/etc/webdav/passwd' ) }
      or return 0;

    return scalar( grep( /^(.+?:){6}/g, split( /\n/, $content ) ) );
}

sub _date2Epoch ($dateStr) {
    my $epoch = 0;

    return 0 unless defined $dateStr;

    # Examples:
    #  [2022-02-27 01:19:10 +0000]
    #  [2021-11-12 17:50:43 +0000]
    #  [2022-03-30 11:01:42 -0500]
    return 0 unless $dateStr =~ /^\[ (\d+)-(\d+)-(\d+) \s (\d+):(\d+):(\d+) \s+ ([\+\-]) (\d+) \]/xmsa;

    my ( $year, $month, $day, $hour, $minute, $second, $plus_minus, $tzoffset );

    $year       = int $1;
    $month      = $2 - 1;    # Make $month zero relative
    $day        = int $3;
    $hour       = int $4;
    $minute     = int $5;
    $second     = int $6;
    $plus_minus = $7;
    $tzoffset   = int $8;

    # sanity check
    return 0
      if $year < 1970
      || $second > 59
      || $minute > 59
      || $hour > 23
      || $day < 1
      || $day > 31
      || $month < 0
      || $month > 11;

    return 0 if grep { $_ <= 0 } $year, $day;
    return 0 if $month < 0;

    return Time::Local::timegm_modern( $second, $minute, $hour, $day, $month, $year );
}

sub _count_recent_logins () {

    my @stats = ( 0, 0 );    # default values

    eval {
        @stats = __count_recent_logins();
        1;
    } or do {
        @stats = ( -1, -1 );
    };

    return @stats;
}

sub __count_recent_logins () {
    my ( %active_users, %impersonated_users );

    my $session_logfile = "$Cpanel::ConfigFiles::CPANEL_ROOT/logs/session_log";

    local $!;

    return ( 0, 0 ) unless -f $session_logfile && -s _;

    require Cpanel::UpdateGatherer::LogReader;

    my $session_log = Cpanel::UpdateGatherer::LogReader->new( $session_logfile, reverse => 1 )
      or die "Unable to open session_log ($session_logfile) - $!";

    # Calculate yesterday's epoch range
    # $end_of_yesterday is obtained by getting time() for today then using
    # local_startof to get the start of today. Finally subtract 1 to get
    # "<yesterday> 23:59:59".
    my $end_of_yesterday = Cpanel::DateUtils::local_startof( time(), 'day' ) - 1;

    # To get $start_of_yesterday we subtract a full day of seconds less 1 second
    # to get the $start_of_yesterday
    my $start_of_yesterday = $end_of_yesterday - ( Time::Piece::ONE_DAY() - 1 );

    my ( $line, $epoch );

    # Traverse $session_log backwards until we get to yesterday
    while ( $line = $session_log->readline ) {
        last if !$line;
        next if $line =~ /^\s*$/;    # skip blank lines

        $epoch = _date2Epoch($line);

        # Nothing in session_log for yesterday!
        if ( $epoch < $start_of_yesterday ) {
            $session_log->close;
            return ( 0, 0 );
        }

        last if $epoch <= $end_of_yesterday;    # Entered $end_of_yesterday range
    }

    # If $line is undefined then we have no more session_log to process
    if ( !$line ) {
        $session_log->close;
        return ( 0, 0 );
    }

    # Processing yesterday
    while (1) {

        # Parsing session_log for logins/impersonations can get tricky. Here's how we're
        # parsing it:
        #
        # . Pay attention only to cpaneld lines
        # . That contain NEW
        # . Of these, ignore Cpanel Tech Support impresonations (possessor =~cptk\w+)
        # . If path=loadsession then it's an impersonation otherwise it's a login
        # . Oauth2 login/impersonations report to session_log just like non-Oauth2
        if ( $line =~ /\[cpaneld\].*NEW\s(\S+):/ ) {
            my $user = $1;

            if ( $line =~ /possessor=(\w+)/ ) {
                my $possessor = $1;

                if ( $line =~ /path=loadsession/ ) {

                    # Not counting Cpanel tech support
                    if ( $possessor !~ /cptk\w+/ ) {
                        $impersonated_users{$user} = 1;
                    }
                }
                else {
                    if ( $possessor eq 'root' ) {

                        # Odd case where user logs in using username but root's password
                        $impersonated_users{$user} = 1;
                    }
                }
            }
            else {
                if ( $line =~ /path=loadsession/ ) {
                    $impersonated_users{$user} = 1;
                }
                else {
                    $active_users{$user} = 1;
                }
            }
        }

        while ( $line = $session_log->readline ) {
            last if !$line;
            next if $line =~ /^\s*$/;    # Skip any blank lines
            last;
        }

        last if !$line;

        $epoch = _date2Epoch($line);

        last if $epoch < $start_of_yesterday;
    }

    $session_log->close;

    return ( scalar keys %active_users, scalar keys %impersonated_users );
}

1;
