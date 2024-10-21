package Cpanel::UpdateGatherer::modules::Mailman;

# cpanel - SOURCES/Mailman.pm                      Copyright 2022 cPanel, L.L.C.
#                                                           All rights reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

use Cpanel::UpdateGatherer::Std;

use Cpanel::Mailman::Filesys ();
use Cpanel::JSON             ();
use Cpanel::SafeRun::Object  ();

sub compile ( $self, $meta ) {
    $self->_add_mailman_list_metrics($meta);
    return 1;
}

sub _add_mailman_list_metrics {
    my ( $self, $meta ) = @_;
    require Cpanel::Config::LoadUserDomains;

    my $domains = Cpanel::Config::LoadUserDomains::loaduserdomains( {}, 0, 1 );

    my $threshold = time - 90 * 24 * 60 * 60;                                                                                                      # No point in doing this repeatedly.
    my %metrics   = ( most_recently_created_at => 0.0, most_recent_last_post_time => 0.0, active_lists => 0, inactive_lists => 0, errors => 0 );
    foreach my $user ( keys %$domains ) {
        foreach my $domain ( @{ $domains->{$user} } ) {
            my ( $ok, $lists ) = Cpanel::Mailman::Filesys::get_list_ids_for_domains($domain);
            if ($ok) {
                foreach my $list (@$lists) {

                    my $saferun = Cpanel::SafeRun::Object->new(
                        'program' => '/usr/local/cpanel/bin/safe_dump_pickle_as_json',
                        'args'    => [
                            Cpanel::Mailman::Filesys::get_list_dir($list) . '/config.pck',
                            'mailman'
                        ],
                    );

                    my $json = $saferun->stdout();

                    if ( !defined $json ) {
                        $metrics{'errors'}++;
                        next;
                    }

                    # Assume only one object in the pickle file.
                    my $config = eval { Cpanel::JSON::Load($json) };
                    if ($@) {
                        $metrics{'errors'}++;
                        next;
                    }

                    # If the last post was 90 days ago or earlier, the list should be considered inactive.
                    if ( $config->{'last_post_time'} > $threshold ) {
                        $metrics{'active_lists'}++;
                    }
                    else {
                        $metrics{'inactive_lists'}++;
                    }

                    $metrics{'most_recently_created_at'}   = $config->{'created_at'}     if $metrics{'most_recently_created_at'} < $config->{'created_at'};
                    $metrics{'most_recent_last_post_time'} = $config->{'last_post_time'} if $metrics{'most_recent_last_post_time'} < $config->{'last_post_time'};
                }
            }
            else {
                $metrics{'errors'}++;
            }
        }
    }

    $meta->{'mailman'} = \%metrics;

    return 1;
}

1;
