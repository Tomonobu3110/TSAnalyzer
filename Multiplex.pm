#!/usr/bin/perl

##########################################################################
# Multiplex object
#   Copyright (C) 2012 Tomonobu Saito All Rights Reserverd.
#   Tomonobu.Saito@gmail.com

package Multiplex;

use strict;
use Carp qw(croak);
use integer;

sub new {
    my $pkg  = shift;
    my $tsid = shift;
    my $onid = shift;
    bless {
        transport_stream_id => $tsid,
        original_network_id => $onid,
        actual              => "",
        frequency           => -1,
        symbol_rate         => -1,
        modulation          => -1,
        band_width          => -1,
        delivery_system     => "???",
    }, $pkg;
}

sub IsSame {
    my $self = shift;
    my $tsid = shift;
    my $onid = shift;
    return 
      $tsid == $self->{ transport_stream_id } &&
      $onid == $self->{ original_network_id };
}

# static method
sub DumpHeaderLine{
    print  "[Multiplex]\n\n";
    print  "tsid   onid   sys act freq(K) BW symbol mod \n";
    print  "------ ------ --- --- ------- -- ------ --- \n"
}

sub Dump {
    my $self = shift;
    printf "0x%04x 0x%04x %s %s %7d %2d %6d %3d \n",
        $self->{ transport_stream_id },
        $self->{ original_network_id },
        $self->{ delivery_system },
        ("a" eq $self->{ actual } ? "act" : "   "),
        $self->{ frequency },
        $self->{ band_width },
        $self->{ symbol_rate },
        $self->{ modulation };
}

#
# Setter
#

sub SetActual {
    my $self = shift;
    if ('a' ne $self->{ actual }) {
        $self->{ actual } = shift;
    }
}

sub SetFrequency {
    my $self = shift;
    $self->{ frequency } = shift;
}

sub SetSymbolRate {
    my $self = shift;
    $self->{ symbol_rate } = shift;
}

sub SetModulation {
    my $self = shift;
    $self->{ modulation } = shift;
}

sub SetBandWidth {
    my $self = shift;
    $self->{ band_width } = shift;
}

sub FromSatellite {
    my $self = shift;
    $self->{ delivery_system } = "sat";
}

sub FromS2 {
    my $self = shift;
    $self->{ delivery_system } = "s2 ";
}

sub FromCable {
    my $self = shift;
    $self->{ delivery_system } = "cbl";
}

sub FromTerr {
    my $self = shift;
    $self->{ delivery_system } = "ter";
}

1;
