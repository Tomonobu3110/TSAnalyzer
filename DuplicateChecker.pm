#!/usr/bin/perl

##########################################################################
# Table Duplicate Checker
#   Copyright (C) 2012 Tomonobu Saito All Rights Reserverd.
#   Tomonobu.Saito@gmail.com

package DuplicateChecker;

use strict;
use Carp qw(croak);
use integer;

sub new {
    my $pkg = shift;
    bless {
        table_id           => undef,
        table_extension_id => undef,
        section_number     => undef,
        version_number     => undef,
    }, $pkg;
}

sub Set {
    my $self = shift;
    my $table_id           = shift;
    my $table_id_extension = shift;
    my $section_number     = shift;
    my $version_number     = shift;

    $self->{ table_id }           = $table_id;
    $self->{ table_id_extension } = $table_id_extension;
    $self->{ section_number }     = $section_number;
    $self->{ version_number }     = $version_number;
}

sub Equal {
    my $self = shift;
    my $table_id           = shift;
    my $table_id_extension = shift;
    my $section_number     = shift;
    
    return
        $self->{ table_id }           == $table_id           &&
        $self->{ table_id_extension } == $table_id_extension &&
        $self->{ section_number }     == $section_number;
}

sub GetNextVersion {
    my $self = shift;
    return ($self->{ version_number } + 1) % 32;
}

sub SetVersion {
    my $self           = shift;
    my $version_number = shift;
    $self->{ version_number } = $version_number;
}

1;
