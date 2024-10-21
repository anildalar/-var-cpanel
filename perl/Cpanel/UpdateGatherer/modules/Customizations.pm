package Cpanel::UpdateGatherer::modules::Customizations;

# cpanel - SOURCES/Customizations.pm               Copyright 2022 cPanel, L.L.C.
#                                                           All rights reserved.
# copyright@cpanel.net                                         http://cpanel.net
# This code is subject to the cPanel license. Unauthorized copying is prohibited

use Cpanel::UpdateGatherer::Std;

use Cpanel::JSON              ();
use Cpanel::Themes::Fallback  ();
use Whostmgr::Resellers::List ();
use Cpanel::YAML              ();

use Cpanel::UpdateGatherer::Std;

=head1 NAME

Cpanel::UpdateGatherer::modules::Customizations

=head1 SYNOPSIS

    use Cpanel::UpdateGatherer::modules::Customizations ();

    my $meta = {};
    Cpanel::UpdateGatherer::modules::Customizations->compile($meta)

=head1 DESCRIPTION

Module for collecting customization usage information from server.

=head1 RETURNS

If the function returns successfully, entry for customizations should
have structure similar to

    {
        'customizations' => {
            'server' => {                  # customizations provided by server administrators
                'company_logo'      => 0,  # if the server has company logo uploaded
                'company_name'      => 0,  # if the server has company name set
                'default_style'     => 0,  # if the server has a default style set
                'default_to_cpanel' => 1,  # if the server uses one of the cpanel provided styles as default style
                'documentation_url' => 0,  # if the server has documentation URL set
                'favicon'           => 0,  # if the server has a favicon uploaded
                'help_url'          => 0,  # if the server has a help URL set
                'includes'          => [], # a list of server-provided UI include files
                'content_includes'  => [], # a list of Jupiter's variant of template Include files
                'reseller_info'     => 0,  # if the server has a reseller information file
                'webmail_logo'      => 0   # if the server has a webmail logo uploaded
            }
        }
    }

=cut

sub compile ( $self, $meta ) {
    _add_customizations_to_metadata($meta);
    return 1;
}

sub _add_customizations_to_metadata ($meta) {
    $meta->{'customizations'} = {};
    _add_server_customizations_to_metadata($meta);
    _add_reseller_customizations_to_metadata($meta);
    _add_root_customizations_to_metadata($meta);
    _add_content_includes_to_metadata($meta);

    #This must run after root and reseller data is gathered
    _add_additional_server_customizations_to_metadata($meta);
    return;
}

sub _add_reseller_customizations_to_metadata ($meta) {

    #The ui include files to check for
    my @includes_files = (
        'global_html_head.html.tt',
        'global_header.html.tt',
        'global_footer.html.tt',
        'above_general_information.html.tt',
        'above_stats_bar.html.tt',
        'below_stats_bar.html.tt',
    );

    #Build a skeleton of the data model to ensure that all keys are always present (even if blank)
    my $data = {
        'total_resellers'                         => 0,
        'total_resellers_with_ui_includes'        => 0,
        'total_resellers_with_branding'           => 0,
        'total_resellers_with_branding_help'      => 0,
        'total_resellers_with_branding_name'      => 0,
        'total_resellers_with_branding_webmail'   => 0,
        'total_resellers_with_branding_docs'      => 0,
        'total_resellers_with_branding_favicon'   => 0,
        'total_resellers_with_branding_logo'      => 0,
        'total_resellers_with_favorites_set'      => 0,
        'total_resellers_with_compact_favorites'  => 0,
        'total_resellers_with_detailed_favorites' => 0,
        'ui_include_points_filled'                => [],
        'reseller_default_styles'                 => [],
        'reseller_favorites'                      => {},
    };

    #iterate through all resellers and count totals
    my $resellers = Whostmgr::Resellers::List::list();
    foreach my $key ( keys %{$resellers} ) {
        if ( $resellers->{$key} == 1 ) {    #Only add them if they're active
            $data->{'total_resellers'}++;
            my $rsdir = Cpanel::Themes::Fallback::get_reseller_directory($key);

            #Check for reseller default style
            my $stylefile = "$rsdir/styled/default_style";    #Get style from the symbolic link for default_style
            if ( -e $stylefile ) {                            #If the file isn't present, there is no default
                my $link = readlink $stylefile;
                if ($link) {
                    my $style = ( split '/', $link )[-1];     #Get the last portion of the style's linked path
                    push @{ $data->{'reseller_default_styles'} }, $style;
                }
            }

            #Check for usage of Reseller branding info
            my $brand_file = "$rsdir/brand/reseller_info.json";
            if ( -e $brand_file ) {
                my $branding = _load_json_file($brand_file);
                $data->{'total_resellers_with_branding'}++;
                if ( $branding->{'company_name'} )                                    { $data->{'total_resellers_with_branding_name'}++; }
                if ( $branding->{'help_url'} )                                        { $data->{'total_resellers_with_branding_help'}++; }
                if ( $branding->{'documentation_url'} )                               { $data->{'total_resellers_with_branding_docs'}++; }
                if ( -e "$rsdir/brand/logo.png" || -e "$rsdir/brand/logo.svg" )       { $data->{'total_resellers_with_branding_logo'}++; }
                if ( -e "$rsdir/brand/webmail.png" || -e "$rsdir/brand/webmail.svg" ) { $data->{'total_resellers_with_branding_webmail'}++; }
                if ( -e "$rsdir/brand/favicon.ico" )                                  { $data->{'total_resellers_with_branding_favicon'}++; }
            }

            #Check for usage of Reseller UI Includes
            my $got_includes = 0;
            foreach my $file (@includes_files) {
                my $include = "$rsdir/includes/$file";
                if ( -e $include ) {
                    $got_includes = 1;
                    push @{ $data->{'ui_include_points_filled'} }, "$file";    #Add
                }
            }
            if ($got_includes) { $data->{total_resellers_with_ui_includes}++; }

            #Check for Favorites/Top Tools customization
            my $nvdata_file = "/var/cpanel/whm/nvdata/$key.yaml";
            if ( -e $nvdata_file ) {
                my $reseller_nvdata = _load_yaml_file($nvdata_file);
                if ( $reseller_nvdata->{'favorites'} ) {
                    $data->{'total_resellers_with_favorites_set'}++;

                    #Compile a hash of all apps favorited by resellers, and how many times they appear
                    foreach my $favorite ( @{ $reseller_nvdata->{'favorites'} } ) {
                        $data->{'reseller_favorites'}->{$favorite}++;
                    }

                    #If user has explicitly set to compact, then increase compact count.
                    #If user has explicitly set to detailed, OR there is no 'showFavoritesDescriptions' entry (default), increase detailed count.
                    if ( exists $reseller_nvdata->{'showFavoritesDescriptions'} && ${ $reseller_nvdata->{'showFavoritesDescriptions'} } == 0 ) {
                        $data->{'total_resellers_with_compact_favorites'}++;
                    }
                    else {
                        $data->{'total_resellers_with_detailed_favorites'}++;
                    }
                }
            }
        }
    }

    #Add the results to metadata
    $meta->{'customizations'}->{'reseller'} = $data;
    return;
}

sub _add_server_customizations_to_metadata ($meta) {
    my $server_customizations = {};

    my $server_default = Cpanel::Themes::Fallback::get_global_directory('/styled') . '/default_style';

    if ( -e $server_default ) {
        $server_customizations->{'default_style'} = 1;
        my $default_path = Cwd::abs_path($server_default);
        $server_customizations->{'default_to_cpanel'} = _is_cpanel_style($default_path);
    }
    else {
        $server_customizations->{'default_style'}     = 0;
        $server_customizations->{'default_to_cpanel'} = 1;
    }

    my $server_brand = Cpanel::Themes::Fallback::get_global_directory('/brand');
    my $server_info  = $server_brand . '/reseller_info.json';
    if ( -e $server_info ) {
        $server_customizations->{'reseller_info'} = 1;

        my $info_hash = _load_json_file($server_info);

        $server_customizations->{'company_name'}      = $info_hash->{'company_name'}      ? 1 : 0;
        $server_customizations->{'help_url'}          = $info_hash->{'help_url'}          ? 1 : 0;
        $server_customizations->{'documentation_url'} = $info_hash->{'documentation_url'} ? 1 : 0;
    }
    else {
        $server_customizations->{'reseller_info'}     = 0;
        $server_customizations->{'company_name'}      = 0;
        $server_customizations->{'help_url'}          = 0;
        $server_customizations->{'documentation_url'} = 0;
    }

    $server_customizations->{'company_logo'} = -e $server_brand . '/logo.png'    ? 1 : 0;
    $server_customizations->{'webmail_logo'} = -e $server_brand . '/webmail.png' ? 1 : 0;
    $server_customizations->{'favicon'}      = -e $server_brand . '/favicon.ico' ? 1 : 0;

    my $server_includes = Cpanel::Themes::Fallback::get_global_directory('/includes');
    if ( -e $server_includes && opendir( my $dh, $server_includes ) ) {
        $server_customizations->{'includes'} = [ sort grep { !/^\./ && !-d $_ } readdir($dh) ];
        closedir $dh;
    }
    else {
        $server_customizations->{'includes'} = [];
    }

    $meta->{'customizations'}->{'server'} = $server_customizations;

    return;
}

sub _add_content_includes_to_metadata ($meta) {
    my $data = [];
    my $dir  = Cpanel::Themes::Fallback::get_global_directory('/content_includes');
    if ( opendir( my $dh, $dir ) ) {
        $data = [ sort grep { /.+\.html\.tt$/ && !-d $_ } readdir($dh) ];
        closedir $dh;
    }
    $meta->{'customizations'}->{'server'}->{'content_includes'} = $data;
    return;
}

sub _add_root_customizations_to_metadata ($meta) {
    my $nvdata_file = "/var/cpanel/whm/nvdata/root.yaml";
    if ( -f $nvdata_file && -s _ ) {
        my $root_nvdata = _load_yaml_file($nvdata_file);
        if ( $root_nvdata->{'favorites'} ) {
            $meta->{'customizations'}->{'root'}->{'favorites_used'} = 1;

            #Compile a hash of all apps favorited by root, and how many times they appear
            foreach my $favorite ( @{ $root_nvdata->{'favorites'} } ) {
                $meta->{'customizations'}->{'root'}->{'favorites'}->{$favorite}++;
            }

            #If root user has explicitly set to compact, then increase compact count.
            #If root user has explicitly set to detailed, OR there is no 'showFavoritesDescriptions' entry (default), increase detailed count.
            if ( exists $root_nvdata->{'showFavoritesDescriptions'} && ${ $root_nvdata->{'showFavoritesDescriptions'} } == 0 ) {
                $meta->{'customizations'}->{'root'}->{'show_favorites_descriptions'} = 0;
            }
            else {
                $meta->{'customizations'}->{'root'}->{'show_favorites_descriptions'} = 1;
            }

            return;
        }
    }

    #Favorites not being used or root nvdata file doesn't exist - we want to make sure all keys are always present (even if blank)
    $meta->{'customizations'}->{'root'}->{'favorites_used'}              = 0;
    $meta->{'customizations'}->{'root'}->{'show_favorites_descriptions'} = 0;
    $meta->{'customizations'}->{'root'}->{'favorites'}                   = {};
    return;
}

sub _load_json_file ($file) {
    return eval { Cpanel::JSON::LoadFile($file) } // {};
}

sub _load_yaml_file ($file) {
    return eval { Cpanel::YAML::LoadFile($file) } // {};
}

sub _add_additional_server_customizations_to_metadata ($meta) {

    #Check if root or resellers are using favorites, and set the server 'favorites_used' accordingly
    my $resellers_using_favorites = $meta->{'customizations'}->{'reseller'}->{'total_resellers_with_favorites_set'} ? 1 : 0;
    my $root_using_favorites      = $meta->{'customizations'}->{'root'}->{'favorites_used'}                         ? 1 : 0;

    $meta->{'customizations'}->{'server'}->{'favorites_used'} = $resellers_using_favorites || $root_using_favorites ? 1 : 0;

    return;
}

sub _is_cpanel_style ($path) {
    return $path =~ m{^/usr/local/cpanel/base} ? 1 : 0;
}

1;
