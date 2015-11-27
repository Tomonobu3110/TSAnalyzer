#!/usr/bin/perl

##########################################################################
# OutWindow
#   Copyright (C) 2012 Tomonobu Saito All Rights Reserverd.
#   Tomonobu.Saito@gmail.com

package OutWindow;

use warnings;
use strict;
use Carp qw(croak);

sub new {
    my $pkg = shift;
    
    bless {
        _buffer     => undef,
        _pos        => undef,
        _windowSize => 0,
        _streamPos  => undef,
        _stream     => undef,
    }, $pkg;
}

sub Create {
    my $self       = shift;
    my $windowSize = shift;
    if (!defined($self->{ _buffer }) || $self->{ _windowSize } != $windowSize) {
        $self->{ _buffer } = [ (undef) x $windowSize ]; # reference of the array.
    }
    $self->{ _windowSize } = $windowSize;
    $self->{ _pos        } = 0;
    $self->{ _streamPos  } = 0;
}

sub SetStream {
    my $self = shift;
    my $rbuf = shift;
    $self->ReleaseStream();
    $self->{ _stream } = $rbuf; # reference to array
}

sub ReleaseStream {
    my $self = shift;
    $self->Flush();
    $self->{ _stream } = undef;
}

sub Init {
    my $self  = shift;
    my $solid = shift;
    
    if (!$solid) {
        $self->{ _streamPos } = 0;
        $self->{ _pos       } = 0;
    }
}

#             v _streamPos     v _pos      v _windowSize
#         ---+----------------+---     -----+
# _buffer    |XXXXXXXXXXXXXXXX|    ...      |
#         ---+----------------+---     -----+
#            :                :
#            : COPY TO STREAM :
#            V                V
#         ---+----------------+
# _stream    |XXXXXXXXXXXXXXXX|
#         ---+----------------+
sub Flush {
    my $self = shift;
    
    my $size = $self->{ _pos } - $self->{ _streamPos };
    if (0 == $size) {
        return;
    }
    
    my $spos = $self->{ _streamPos };
    my $epos = $self->{ _pos       } - 1;
    push(@{$self->{ _stream }}, @{$self->{ _buffer }}[$spos .. $epos]);
    if ($self->{ _windowSize } <= $self->{ _pos }) {
        $self->{ _pos } = 0;
    }
    $self->{ _streamPos } = $self->{ _pos };
}

sub CopyBlock {
    my $self     = shift;
    my $distance = shift;
    my $len      = shift;
    
    my $pos = $self->{ _pos } - $distance - 1;
    if ($pos < 0) {
        $pos += $self->{ _windowSize };
    }

    for (; $len != 0; $len--) {
        if ($pos >= $self->{ _windowSize }) {
            $pos = 0;
        }
        ${$self->{ _buffer }}[$self->{ _pos }] = ${$self->{ _buffer }}[$pos];
        ++($self->{ _pos });
        ++$pos;
        if ($self->{ _pos } >= $self->{ _windowSize }) {
            $self->Flush();
        }
    }
}

sub PutByte {
    my $self = shift;
    my $b    = shift; # byte
    
    ${$self->{ _buffer }}[$self->{ _pos }] = ($b & 0xFF); # byte
    ++$self->{ _pos };
    
    if ($self->{ _pos } >= $self->{ _windowSize }) {
        $self->Flush();
    }
}

sub GetByte {
    my $self     = shift;
    my $distance = shift;
    
    my $pos = $self->{ _pos } - $distance - 1;
    if ($pos < 0) {
        $pos += $self->{ _windowSize };
    }
    return ${$self->{ _buffer }}[$pos];
}

1;
