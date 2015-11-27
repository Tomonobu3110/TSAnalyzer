#!/usr/bin/perl

##########################################################################
# Service object
#   Copyright (C) 2012 Tomonobu Saito All Rights Reserverd.
#   Tomonobu.Saito@gmail.com

package Service;

use strict;
use Carp qw(croak);
use integer;

use LCN;

sub new {
    my $pkg   = shift;
    my $tsid  = shift;
    my $onid  = shift;
    my $svcid = shift;
    bless {
        transport_stream_id   => $tsid,
        original_network_id   => $onid,
        service_id            => $svcid,
        origin                => 0,
        actual                => "",
        service_type          => -1,
        service_provider_name => "",
        service_name          => "",
        EIT_schedule          => -1,
        EIT_pf                => -1,
        running_status        => -1,
        free_CA               => -1,
        ref_lcn_list          => [], # reference of no-name array.
    }, $pkg;
}

sub IsSame {
    my $self  = shift;
    my $tsid  = shift;
    my $onid  = shift;
    my $svcid = shift;
    return 
      $tsid  == $self->{ transport_stream_id } &&
      $onid  == $self->{ original_network_id } &&
      $svcid == $self->{ service_id };
}

# static method
sub DumpHeaderLine{
    print "[Service]\n\n";
    print "tsid   onid   svcid  lcn  vf org act type EIT run CA\n";
    print "------ ------ ------ ---- -- --- --- ---- --- --- --\n"
}

sub Dump {
    my $self = shift;

    # default LCN object
    my $default_lcn = $self->find_lcn_entry("default");
    
    printf "0x%04x 0x%04x 0x%04x %4d %2d %s%s%s %s %4d %s%s %3d %2d %s\n",
        $self->{ transport_stream_id },
        $self->{ original_network_id },
        $self->{ service_id },
        $default_lcn->{ lcn },
        $default_lcn->{ visible_service_flag },
        (0 != (0x01 & $self->{ origin }) ? "N" : " "), # from NIT
        (0 != (0x02 & $self->{ origin }) ? "B" : " "), # from BAT
        (0 != (0x04 & $self->{ origin }) ? "S" : " "), # from SDT
        ("a" eq $self->{ actual } ? "act" : "   "),
        $self->{ service_type },
        (1 == $self->{ EIT_schedule } ? "s"  : " " ),
        (1 == $self->{ EIT_pf       } ? "pf" : "  "),
        $self->{ running_status },
        $self->{ free_CA },
        $self->{ service_name };
    
    # LCN
    my $ref_list = $self->{ ref_lcn_list };
    my @lcn_list = @$ref_list;
    foreach my $lcn (@lcn_list) {
      unless ($lcn->IsSame("default")) {
            printf "           other lcn %4d %2d (%s)\n",
                  $lcn->{ lcn },         #
                  $lcn->{ visible_service_flag },
                  $lcn->{ identifier };
        }
    }
}

#
# Setter
#

sub FromNIT {
    my $self = shift;
    $self->{ origin } |= 0x01;
}

sub FromBAT {
    my $self = shift;
    $self->{ origin } |= 0x02;
}

sub FromSDT {
    my $self = shift;
    $self->{ origin } |= 0x04;
}

sub SetActual {
    my $self = shift;
    $self->{ actual } = shift;
}

sub SetServiceType {
    my $self = shift;
    $self->{ service_type } = shift;
}

sub SetServiceProviderName {
    my $self = shift;
    $self->{ service_provider_name } = shift;
}

sub SetServiceName {
    my $self = shift;
    $self->{ service_name } = shift;
}

sub SetEitFlag {
    my $self = shift;
    $self->{ EIT_schedule } = shift;
    $self->{ EIT_pf }       = shift;
}

sub SetRunningStatus {
    my $self = shift;
    $self->{ running_status } = shift;
}

sub SetFreeCA {
    my $self = shift;
    $self->{ free_CA } = shift;
}

sub SetVisibleServiceFlag {
    my $self = shift;
    my $lcn  = $self->find_lcn_entry(shift);
    $lcn->SetVisibleServiceFlag(shift);
}

sub SetLCN {
    my $self = shift;
    my $lcn  = $self->find_lcn_entry(shift);
    $lcn->SetLCN(shift);
}

sub find_lcn_entry {
    my $self  = shift;
    my $ident = shift;

    my $ref_list = $self->{ ref_lcn_list };
    my @lcn_list = @$ref_list;
    foreach my $lcn (@lcn_list) {
        if ($lcn->IsSame($ident)) {
            return $lcn;
        }
    }
    
    my $new_lcn = new LCN($ident);
    push(@lcn_list, $new_lcn);
    $self->{ ref_lcn_list } = \@lcn_list; # copy back
    return $new_lcn;
}

1;
