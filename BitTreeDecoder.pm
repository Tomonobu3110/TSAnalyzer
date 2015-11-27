#!/usr/bin/perl

##########################################################################
# Bit Tree Decoder
#   Copyright (C) 2012 Tomonobu Saito All Rights Reserverd.
#   Tomonobu.Saito@gmail.com

package BitTreeDecoder;

use warnings;
use strict;
use Carp qw(croak);

use RangeCoderDecoder;

sub new {
    my $pkg          = shift;
    my $numBitLevels = shift;

    bless {
        NumBitLevels => $numBitLevels,
        ref_Models   => [ (undef) x (1 << $numBitLevels) ],
    }, $pkg;
}

sub Init {
    my $self = shift;
    RangeCoderDecoder::InitBitModels($self->{ ref_Models });
}

sub Decode {
    my $self         = shift;
    my $rangeDecoder = shift;

    my $m = 1;
    for (my $bitIndex = $self->{ NumBitLevels }; 0 != $bitIndex ; --$bitIndex) {
        $m = ($m << 1) + $rangeDecoder->DecodeBit($self->{ ref_Models }, $m);
    }
    return $m - (1 << $self->{ NumBitLevels });
}

sub ReverseDecode {
    my $self         = shift;
    my $rangeDecoder = shift;
    
    my $m      = 1;
    my $symbol = 0;
    for (my $bitIndex = 0; $bitIndex < $self->{ NumBitLevels }; ++$bitIndex) {
        my $bit = $rangeDecoder->DecodeBit($self->{ ref_Models }, $m);
        $m = $m << 1;
        $m += $bit;
        $symbol |= ($bit << $bitIndex);
    }
    return $symbol;
}

# static
sub ReverseDecode_static {
    my $ref_Models   = shift;
    my $startIndex   = shift;
    my $rangeDecoder = shift;
    my $NumBitLevels = shift;
    
    my $m      = 1;
    my $symbol = 0;
    for (my $bitIndex = 0; $bitIndex < $NumBitLevels; ++$bitIndex) {
        my $bit = $rangeDecoder->DecodeBit($ref_Models, $startIndex + $m);
        $m = $m << 1;
        $m += $bit;
        $symbol |= ($bit << $bitIndex);
    }
    return $symbol;
}

1;
