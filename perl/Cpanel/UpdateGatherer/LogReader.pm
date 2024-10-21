package Cpanel::UpdateGatherer::LogReader;

# cpanel - SOURCES/LogReader.pm                    Copyright 2022 cPanel, L.L.C.
#                                                           All rights reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

use strict;
use warnings;

use Cpanel::Autodie ();

use IO::Uncompress::Gunzip ();
use File::MMagic           ();
use File::Basename         ();
use File::ReadBackwards    ();

=head1 NAME

C<Cpanel::UpdateGatherer::LogReader>ls

=head1 SYNOPSIS

    use Cpanel::UpdateGatherer::LogReader ();

    my $logreader = Cpanel::UpdateGatherer::LogReader->new ( 'session_log' );

    while (my $line = $logreader->readline) {
        # do something with $line
    }

=head1 DESCRIPTION

Present a Cpanel system logfile and any of its rotated (compressed) logfiles as
a single stream that can be read forwards from earliest date to the current
logfile or backwards from the current logfile to the earliest date. Archived
logfiles are decompressed B<only> when read backwards. The contents of the
logfiles are not interrogated and it is assumed that additional logfiles reside
under a directory named archive that are compressed and following a naming
structure of <logfile name>-MM-YYYY.gz.

=head1 RETURNS

Returns a line from the logstream or undef when the end of stream is reached

=cut

# Given a base log filename (e.g. /usr/local/cpanel/logs/session_log) return a list of log files
sub _get_filelist {
    my ( $self, $filename ) = @_;

    my ( $name, $path ) = File::Basename::fileparse($filename);
    my $archives = $path . "archive/$name";

    my @filelist = glob("$archives*");

    my %logs;

    # Need to sort archives by proper date order
    foreach my $archive (@filelist) {
        if ( $archive =~ /.*\-(\d+)\-(\d+)\.gz/ ) {
            $logs{"$2$1"} = $archive;
        }
    }

    @filelist = ();

    if ( $self->{'reverse'} ) {
        push @filelist, $logs{$_} foreach sort { $b cmp $a } keys %logs;
        unshift @filelist, $filename;
    }
    else {
        push @filelist, $logs{$_} foreach sort keys %logs;
        push @filelist, $filename;
    }

    return @filelist;
}

sub _is_gzip {
    my ($filename) = @_;

    my $mm = File::MMagic->new();

    return $mm->checktype_filename($filename) =~ /gzip/;
}

sub _open_log {
    my ($self) = @_;

    my $filename = shift @{ $self->{'filelist'} };

    return if !$filename;

    if ( _is_gzip($filename) ) {
        if ( $self->{'reverse'} ) {
            my ( $name, $path, $suffix ) = fileparse( $filename, qw(.gz) );

            $self->{'temp_decompressed_file'} = "$path/$name.$$";

            # If the logs are to be read by File::ReadBackwards then they need to be first uncompressed.
            # This can be costly but there's no better way to do it.
            IO::Uncompress::Gunzip::gunzip( $filename, $self->{'temp_decompressed_file'} ) or die "Unable to decompress $filename - $!";

            $self->{'fh'} = File::ReadBackwards->new( $self->{'temp_decompressed_file'} )
              or die "Unable to open decompressed logfile $self->{'temp_decompressed_file'} - $!";
        }
        else {
            $self->{'fh'} = IO::Uncompress::Gunzip->new($filename)
              or die "Unable to open compressed logfile $filename - $!";
        }
    }
    else {
        if ( $self->{'reverse'} ) {
            $self->{'fh'} = File::ReadBackwards->new($filename)
              or die "Unable to open logfile $filename - $!";
        }
        else {
            open( $self->{'fh'}, '<', $filename )
              or die "Unable to open logfile $filename";
        }
    }

    return 1;
}

=head1 METHODS

Constructs LogReader object

=head2 new($filename)

INPUT:
    filename - path to logfile

OUTPUT:
    LogReader object

NOTE:

If $options{reverse} == 1 then we read the files using File::ReadBackwards. Since archive
logfiles are kept gzipped and because there is no easy way to use File::ReadBackwards on a
gzipped file, compressed logfiles are ungzipped and will be removed when no longer
needed. This can incur a lot of overhead to uncompress these files.

=cut

sub new {
    my ( $class, $filename, %options ) = @_;

    my $self = bless {
        'reverse' => $options{reverse},
    }, $class;

    die "Logfile '$filename' not found" if !-e $filename;

    # Generate filelist of logfiles to read
    @{ $self->{'filelist'} } = $self->_get_filelist($filename);

    $self->_open_log();

    return $self;
}

=head2 readline()

Reads a line from the logstream

INPUT:
    none

OUTPUT:
    Returns a line from the logstream or undef when the stream is exhausted

=cut

sub readline {
    my ($self) = @_;

    my $line = $self->{'fh'}->getline();

    if ( !$line ) {
        $self->close();

        return if !$self->_open_log();

        $line = $self->{'fh'}->getline();
    }

    return $line;
}

=head2 close()

Closes logstream

INPUT:
    none

OUTPUT:
    none

=cut

sub close {
    my ($self) = @_;

    if ( $self->{'temp_decompressed_file'} ) {
        Cpanel::Autodie::unlink_if_exists( $self->{'temp_decompressed_file'} );

        undef $self->{temp_decompressed_file};
    }

    if ( $self->{'fh'} ) {
        if ( ref $self->{'fh'} eq "File::ReadBackwards" ) {
            $self->{'fh'}->close();
        }
        else {
            close $self->{'fh'};
        }
    }

    undef $self->{'fh'};

    return;
}

sub DESTROY {
    my ($self) = @_;

    $self->close();

    return;
}

1;
