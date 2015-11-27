#!/usr/bin/perl

##########################################################################
# Range Coder / Decoder
#   Copyright (C) 2012 Tomonobu Saito All Rights Reserverd.
#   Tomonobu.Saito@gmail.com

package RangeCoderDecoder;

use warnings;
use strict;
use Carp qw(croak);

use constant kTopMask              => ~((1 << 24) - 1);
use constant kNumBitModelTotalBits => 11;
use constant kBitModelTotal        => 1 << kNumBitModelTotalBits;
use constant kNumMoveBits          => 5;

sub new {
    my $pkg = shift;
    bless {
        range      => undef,
        code       => undef,
        ref_buffer => undef,
    }, $pkg;
}

sub SetStream {
    my $self = shift;
    my $rbuf = shift;
    $self->{ ref_buffer } = $rbuf; # reference to array
}

sub ReleaseStream {
    my $self = shift;
    $self->{ ref_buffer } = undef;
}

sub Init {
    my $self = shift;
    $self->{ code  } =  0;
    $self->{ range } = -1;
    for (my $i = 0; $i < 5; ++$i) {
        $self->{ code } = ($self->{ code } << 8) | shift(@{$self->{ ref_buffer }});
    }
}

sub DecodeDirectBits {
    my $self         = shift;
    my $numTotalBits = shift;
    
    my $result = 0;
    for (my $i = $numTotalBits; 0 != $i; --$i) {
        $self->{ range } = $self->{ range } >> 1;
        my $t = (($self->{ code } - $self->{ range }) >> 31);
        $self->{ code } -= $self->{ range } & ($t - 1);
        $result = ($result << 1) | (1 - $t);
        
        if (0 == ($self->{ range } & kTopMask)) {
            $self->{ code  } = ($self->{ code } << 8) | shift(@{$self->{ ref_buffer }});
            $self->{ range } = $self->{ range } << 8;
        }
    }
    return $result;
}

sub DecodeBit {
    my $self      = shift;
    my $ref_probs = shift; # reference to array (of short)
    my $index     = shift;
    
    my $prob = $$ref_probs[$index] & 0xFFFF; # short
    my $newBound = ($self->{ range } >> kNumBitModelTotalBits) * $prob;
    #printf "code 0x%x(0x%x) nb 0x%x(0x%x)\n", 
    #    $self->{ code }, ($self->{ code } ^ 0x80000000), $newBound, ($newBound ^ 0x80000000);
    my $signed_cd = unpack("i", pack("I", ($self->{ code } ^ 0x80000000)));
    my $signed_nb = unpack("i", pack("I", ($newBound       ^ 0x80000000)));
    if ($signed_cd < $signed_nb) {
        $self->{ range } = $newBound;
        $$ref_probs[$index] = ($prob + ((kBitModelTotal - $prob) >> kNumMoveBits)) & 0xFFFF; # short
        if (0 == ($self->{ range } & kTopMask)) {
            $self->{ code  } = ($self->{ code } << 8) | shift(@{$self->{ ref_buffer }});
            $self->{ range } <<= 8;
        }
        #printf "DecodeBit --> 0 (code 0x%x range 0x%x nb 0x%x prob 0x%x probs 0x%x index %d)\n", $self->{ code }, $self->{ range }, $newBound, $prob, $$ref_probs[$index], $index;
        return 0;
    }
    else {
        $self->{ range } -= $newBound;
        $self->{ code  } -= $newBound;
        $$ref_probs[$index] = ($prob - (($prob) >> kNumMoveBits)) & 0xFFFF; # short
        if (0 == ($self->{ range } & kTopMask)) {
            $self->{ code  } = ($self->{ code } << 8) | shift(@{$self->{ ref_buffer }});
            $self->{ range } <<= 8;
        }
        #printf "DecodeBit --> 1 (code 0x%x range 0x%x nb 0x%x prob 0x%x probs 0x%x index %d)\n", $self->{ code }, $self->{ range }, $newBound, $prob, $$ref_probs[$index], $index;
        return 1;
    }
}

# static
sub InitBitModels {
    my $ref_probs = shift; # reference to array

    for (my $i = 0; $i < @$ref_probs; ++$i) {
        $$ref_probs[$i] = (kBitModelTotal >> 1);
    }
}

1;
