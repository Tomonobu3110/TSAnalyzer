#!/usr/bin/perl

##########################################################################
# Packet Buffer Handler
#   Copyright 2012, Tomonobu Saito
#   Tomonobu.Saito@gmail.com

package PacketBuffer;

use strict;
use Carp qw(croak);
use integer;

sub new {
    my $pkg = shift;
    bless {
        pid   => undef,
        buf   => [],
        index => undef,
    }, $pkg;
}

sub Init {
    my $self  = shift;
    my $pid   = shift;
    my $index = shift;
    my $rbuff = shift; # refernece to array
    
    # copy
    $self->{ buf } = [];
    push(@{$self->{ buf }}, @$rbuff);
    $self->{ pid   } = $pid;
    $self->{ index } = $index;
}

sub Add {
    my $self  = shift;
    my $index = shift;
    my $rbuff = shift; # refernece to array

    push(@{$self->{ buf }}, @$rbuff);
    $self->{ index } = $index;
}

sub GetBuffer {
    my $self = shift;
    return @{$self->{ buf }};
}

sub GetSize {
    my $self = shift;
    return $#{$self->{ buf }};
}

sub GetPID {
    my $self = shift;
    return $self->{ pid };
}

sub GetIndex {
    my $self = shift;
    return $self->{ index };
}

sub Dump {
    my $self = shift;

    print "===== DUMP BEGIN =====\n";
    my($i);
    foreach $b (@{$self->{ buf }}) {
        printf "0x%02X ", $b;
        if (0 == (($i + 1) % 8)) { 
            print "\n";
        }
        $i += 1;
    }
    print "\n===== DUMP END =======\n";
}

1;
