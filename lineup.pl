#!/usr/bin/perl

##########################################################################
# MUX/Service Lineup
#   Copyright (C) 2012 Tomonobu Saito All Rights Reserved.
#   Tomonobu.Saito@gmail.com

use strict;
use warnings;

use Multiplex;
use Service;

#====================================================================
# CONFIGRATION { BEGIN }
#====================================================================

#====================================================================
# CONFIGRATION { END }
#====================================================================

# list
my @mux_list;
my @svc_list;

parse_loop();
print_loop();

exit(0);


##########################################################################
#
# parse_loop
#
sub parse_loop {

    # current parameter
    my $mode = 0;
    my $tag  = 0;
    my $actual;
    my $pid;
    my $table_id;
    my $table_extension_id;
    my $transport_stream_id;
    my $original_network_id;
    my $service_id;
    my $lcn_v2_list_id;
    my $lcn_v2_list_name;
    my $lcn_v2_country;
    
    while (my $i = <STDIN>) {
        $i =~ s/[\r\n\x1a]+$//; #RTRIM(0x1a = EOF)

        #
        # parser mode transition
        #
        if ($i =~ /NIT(a|o) FOUND \([0-9]+\) PID:0x([0-9A-F]+) tbl:0x([0-9A-F]+) ext:0x([0-9A-F]+)/) { 
            $mode               = 1;
            $actual             = $1;
            $pid                = hex($2);
            $table_id           = hex($3);
            $table_extension_id = hex($4);
#           printf "NIT found 0x%x 0x%x 0x%x\n", $pid, $table_id, $table_extension_id;
        }
        elsif ($i =~ /BAT FOUND \([0-9]+\) PID:0x([0-9A-F]+) tbl:0x([0-9A-F]+) ext:0x([0-9A-F]+)/) { 
            $mode               = 2;
            $actual             = 'b'; # BAT
            $pid                = hex($1);
            $table_id           = hex($2);
            $table_extension_id = hex($3);
#           printf "BAT found 0x%x 0x%x 0x%x\n", $pid, $table_id, $table_extension_id;
        }
        elsif ($i =~ /SDT(a|o) FOUND \([0-9]+\) PID:0x([0-9A-F]+) tbl:0x([0-9A-F]+) ext:0x([0-9A-F]+)/) {
            $mode               = 3;
            $actual             = $1;
            $pid                = hex($2);
            $table_id           = hex($3);
            $table_extension_id = hex($4);
#           printf "SDT found 0x%x 0x%x 0x%x\n", $pid, $table_id, $table_extension_id;
        }
        
        #
        # descriptor tag
        #
        if ($i =~ /tag:0x([0-9a-fA-F]+) len:([0-9a-fA-F]+)/) {
            $tag = hex($1);
        }

        #
        # NIT/BAT parser
        #
        if (1 == $mode || 2 == $mode) {
            if ($i =~ /NIT END/ || $i =~ /BAT END/) {
                $mode = 0;
                next; # continue;
            }
            elsif ($i =~ /tsid 0x([0-9a-fA-F]+) onid 0x([0-9a-fA-F]+)/) {
                $transport_stream_id = hex($1);
                $original_network_id = hex($2);
                my $mux = find_multiplex($transport_stream_id, $original_network_id);
                $mux->SetActual($actual);
            }
            # service list descriptor
            elsif (0x41 == $tag && $i =~ /service_id 0x([0-9a-fA-F]+) service_type 0x([0-9a-fA-F]+)/) {
                $service_id = hex($1);
                my $svc = find_service($transport_stream_id, $original_network_id, $service_id);
                if (1 == $mode) {
                    $svc->FromNIT();
                } else {
                    $svc->FromBAT();
                }
                $svc->SetServiceType($2);
            }
            # satellite delivery system descriptor
            elsif (0x43 == $tag && $i =~ /frequency[ ]+([0-9]+)/) {
                my $mux = find_multiplex($transport_stream_id, $original_network_id);
                $mux->SetFrequency($1);
            }
            elsif (0x43 == $tag && $i =~ /symbol_rate[ ]+([0-9]+)/) {
                my $mux = find_multiplex($transport_stream_id, $original_network_id);
                $mux->SetSymbolRate($1);
            }
            elsif (0x43 == $tag && $i =~ /modulation_system[ ]+([0-9]+)/) {
                my $mux = find_multiplex($transport_stream_id, $original_network_id);
                if    (0 == $1) { $mux->FromSatellite(); }
                elsif (1 == $1) { $mux->FromS2(); }
            }
            elsif (0x43 == $tag && $i =~ /modulation_type[ ]+([0-9]+)/) {
                my $mux = find_multiplex($transport_stream_id, $original_network_id);
                $mux->SetModulation($1);
            }
            # cable delivery system descriptor
            elsif (0x44 == $tag && $i =~ /frequency[ ]+([0-9]+)/) {
                my $mux = find_multiplex($transport_stream_id, $original_network_id);
                $mux->FromCable();
                $mux->SetFrequency(int($1 / 10));
            }
            elsif (0x44 == $tag && $i =~ /symbol_rate[ ]+([0-9]+)/) {
                my $mux = find_multiplex($transport_stream_id, $original_network_id);
                $mux->SetSymbolRate($1);
            }
            elsif (0x44 == $tag && $i =~ /modullation[ ]+0x([0-9a-fA-F]+)/) {
                my $mux = find_multiplex($transport_stream_id, $original_network_id);
                $mux->SetModulation($1);
            }
            # delivery system descriptor
            elsif (0x5a == $tag && $i =~ /center_frequency[ ]+([0-9]+)/) {
                my $mux = find_multiplex($transport_stream_id, $original_network_id);
                $mux->FromTerr();
                $mux->SetFrequency(int($1 / 100));
            }
            elsif (0x5a == $tag && $i =~ /band_width[ ]+([0-9]+)MHz/) {
                my $mux = find_multiplex($transport_stream_id, $original_network_id);
                $mux->FromTerr();
                $mux->SetBandWidth($1);
            }
            # LCN
            elsif (0x83 == $tag && $i =~ /service_id[ ]+0x([0-9a-fA-F]+)/) {
                $service_id = hex($1);
            }
            elsif (0x83 == $tag && $i =~ /visible_service_flag[ ]+(0|1)/) {
                my $svc = find_service($transport_stream_id, $original_network_id, $service_id);
                $svc->SetVisibleServiceFlag("default", $1);
            }
            elsif (0x83 == $tag && $i=~ /lcn[ ]+([0-9]+)/) {
                my $svc = find_service($transport_stream_id, $original_network_id, $service_id);
                $svc->SetLCN("default", $1);
            }
            # HD simulcast LCN
            elsif (0x88 == $tag && $i =~ /service_id[ ]+0x([0-9a-fA-F]+)/) {
                $service_id = hex($1);
            }
            elsif (0x88 == $tag && $i =~ /visible_service_flag[ ]+(0|1)/) {
                my $svc = find_service($transport_stream_id, $original_network_id, $service_id);
                $svc->SetVisibleServiceFlag("HD simulcast", $1);
            }
            elsif (0x88 == $tag && $i=~ /lcn[ ]+([0-9]+)/) {
                my $svc = find_service($transport_stream_id, $original_network_id, $service_id);
                $svc->SetLCN("HD simulcast", $1);
            }
            # LCN V2
            elsif (0x87 == $tag && $i =~ /channel_list_id ([0-9]+)/) {
                $lcn_v2_list_id = $1;
            }
            elsif (0x87 == $tag && $i =~ /channel_list_name\([0-9]+\) ([0-9a-zA-Z ]+)/) {
                $lcn_v2_list_name = $1;
            }
            elsif (0x87 == $tag && $i =~ /country_code ([a-zA-Z]+)/) {
                $lcn_v2_country = $1;
            }
            elsif (0x87 == $tag && $i =~ /service_id[ ]+0x([0-9a-fA-F]+)/) {
                $service_id = hex($1);
            }
            elsif (0x87 == $tag && $i =~ /visible_service_flag[ ]+(0|1)/) {
                my $svc = find_service($transport_stream_id, $original_network_id, $service_id);
                my $ident = $lcn_v2_list_id . "/" . $lcn_v2_country . "/" . $lcn_v2_list_name;
                $svc->SetVisibleServiceFlag("LCN V2 " . $ident, $1);
            }
            elsif (0x87 == $tag && $i=~ /lcn[ ]+([0-9]+)/) {
                my $svc = find_service($transport_stream_id, $original_network_id, $service_id);
                my $ident = $lcn_v2_list_id . "/" . $lcn_v2_country . "/" . $lcn_v2_list_name;
                $svc->SetLCN("LCN V2 " . $ident, $1);
            }
        }
        
        #
        # SDT parser
        #
        if (3 == $mode) {
            if ($i =~ /SDT END/) {
                $mode = 0;
                next; # continue;
            }
            elsif ($i =~ /tsid 0x([0-9a-fA-F]+) onid 0x([0-9a-fA-F]+) svcid 0x([0-9a-fA-F]+) EITs\/p (0|1)\/(0|1) running ([0-9]+) free_CA (0|1)/) {
                # basical parameters
                $transport_stream_id = hex($1);
                $original_network_id = hex($2);
                $service_id          = hex($3);
                my $svc = find_service($transport_stream_id, $original_network_id, $service_id);
                # other parameters
                $svc->FromSDT();
                $svc->SetActual($actual);
                $svc->SetEitFlag($4, $5);
                $svc->SetRunningStatus($6);
                $svc->SetFreeCA($7);
            }
            # service descriptor
            elsif (0x48 == $tag && $i =~ /service_type 0x([0-9a-fA-F]+)/) {
                my $svc = find_service($transport_stream_id, $original_network_id, $service_id);
                $svc->SetServiceType(hex($1));
            }
            elsif (0x48 == $tag && $i =~ /service_provider_name\([0-9]+\) (.*)$/) {
                my $svc = find_service($transport_stream_id, $original_network_id, $service_id);
                $svc->SetServiceProviderName($1);
            }
            elsif (0x48 == $tag && $i =~ /service_name\([0-9]+\) (.*)$/) {
                my $svc = find_service($transport_stream_id, $original_network_id, $service_id);
                $svc->SetServiceName($1);
            }
        }
    }
}

##########################################################################
#
# print_loop
#
sub print_loop {
    print "\n";
    dump_service_list();
    print "\n";
    dump_multiplex_list();
}

##########################################################################
#
# find multiplex object
#
sub find_multiplex
{
    my $tsid = shift;
    my $onid = shift;
    
    foreach my $m (@mux_list) {
        if ($m->IsSame($tsid, $onid)) {
            return $m;
        }
    }
    
    # creation of new multiplex object
    my $new_mux = new Multiplex($tsid, $onid);
    push(@mux_list, $new_mux);
    return $new_mux;
}

##########################################################################
#
# find service object
#
sub find_service
{
    my $tsid  = shift;
    my $onid  = shift;
    my $svcid = shift;
    
    foreach my $s (@svc_list) {
        if ($s->IsSame($tsid, $onid, $svcid)) {
            return $s;
        }
    }
    
    # creation of new service object
    my $new_svc = new Service($tsid, $onid, $svcid);
    push(@svc_list, $new_svc);
    return $new_svc;
}

##########################################################################
#
# dump service list
#
sub dump_service_list
{
    Service->DumpHeaderLine();
    foreach my $s (@svc_list) {
        $s->Dump();
    }
}

##########################################################################
#
# dump multiplex list
#
sub dump_multiplex_list
{
    Multiplex->DumpHeaderLine();
    foreach my $m (@mux_list) {
        $m->Dump();
    }
}
