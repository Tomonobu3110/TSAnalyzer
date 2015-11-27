#!/usr/bin/perl

##########################################################################
# TS Packet Analyzer
#   Copyright (C) 2012 Tomonobu Saito All Rights Reserverd.
#   Tomonobu.Saito@gmail.com

package TSPacket;

use strict;
use Carp qw(croak);
use integer;

sub new {
    my $pkg = shift;
    bless {
        ref_buf  => [],
        byte_ptr => undef,
        bit_ptr  => undef,
        sect_len => undef,
        desc_len => undef,
        head_ptr => undef,
        tail_ptr => undef,
    }, $pkg;
}

sub SetBuffer {
    my $self = shift;
    my $rbuf = shift;
    $self->{ ref_buf  } = $rbuf; # reference to array
    $self->{ byte_ptr } =     0;
    $self->{ bit_ptr  } =     0;
}

sub EOF {
    my $self   = shift;
    my $rbuf = $self->{ ref_buf }; # reference to array
    my @buf  = @$rbuf;
    return $#buf < $self->{ byte_ptr };
}

sub SetHeadPointer {
    my $self   = shift;
    if (0 != $self->{ bit_ptr }) {
        print "*** WARNING : bit pointer is not 0 ***\n";
    }
    $self->{ head_ptr } = $self->{ byte_ptr };
    
    # length check
    my $rbuf = $self->{ ref_buf }; # reference to array
    my @buf  = @$rbuf;
    return $self->{ head_ptr } <= $#buf;
}

sub SetBodyLength {
    my $self   = shift;
    my $length = shift;

    if (0 != $self->{ bit_ptr }) {
        print "*** WARNING : bit pointer is not 0 ***\n";
    }
    $self->{ tail_ptr } = ($self->{ byte_ptr }) + $length - 1;

    # length check
    my $rbuf = $self->{ ref_buf }; # reference to array
    my @buf  = @$rbuf;
    return $self->{ tail_ptr } <= $#buf;
}

sub GetBody {
    my $self   = shift;
    
    my $rbuf = $self->{ ref_buf }; # reference to array
    my @buf  = @$rbuf;
    
    return @buf[$self->{ head_ptr }..$self->{ tail_ptr }];
}

sub SkipToNextSection {
    my $self   = shift;
    $self->{ byte_ptr } = $self->{ tail_ptr } + 1;
    $self->{ bit_ptr  } = 0;
}

sub SetSectionLength {
    my $self   = shift;
    my $length = shift;
    
    if (0 != $self->{ bit_ptr }) {
        print "*** WARNING : bit pointer is not 0 ***\n";
    }
    $self->{ sect_len } = ($self->{ byte_ptr }) + $length;
}

sub GetRemainBytesOfSection {
    my $self = shift;
    return ($self->{ sect_len }) - ($self->{ byte_ptr });
}

sub SetDescriptorLength {
    my $self   = shift;
    my $length = shift;
    
    if (0 != $self->{ bit_ptr }) {
        print "*** WARNING : bit pointer is not 0 ***\n";
    }
    $self->{ desc_len } = ($self->{ byte_ptr }) + $length;
}

sub GetRemainBytesOfDescriptor {
    my $self = shift;
    return ($self->{ desc_len }) - ($self->{ byte_ptr });
}

sub Dump {
    my $self = shift;

    my $rbuf = $self->{ ref_buf }; # reference to array
    my @buf  = @$rbuf;
    
    print "===== DUMP BEGIN =====\n";
    for (my $i = 0; $i < $#buf + 1; ++$i) {
        printf "%02X ", $buf[$i];
        if (0 == (($i + 1) % 16)) { 
            print "\n";
        }
        elsif (0 == (($i + 1) % 8)) {
            print "- ";
        }
    }
    print "\n===== DUMP END =======\n";
}

sub Skip {
    my $self = shift;
    my $bits = shift;

    my $rbuf = $self->{ ref_buf }; # reference to array
    my @buf  = @$rbuf;

    $self->{ byte_ptr } += int($bits / 8);
    $self->{ bit_ptr  } += ($bits % 8);
    while (8 <= $self->{ bit_ptr }) {
        $self->{ byte_ptr } += 1;
        $self->{ bit_ptr }  -= 8;
    }
    
    if ($#buf + 1 <= $self->{ byte_ptr } && 0 < $self->{ bit_ptr }) {
        print "*** ERROR : byte pointer is $self->{ byte_ptr } ***\n";
    }
}

sub SkipBytes {
    my $self  = shift;
    my $bytes = shift;

    my $rbuf = $self->{ ref_buf }; # reference to array
    my @buf  = @$rbuf;

    $self->{ byte_ptr } += $bytes;

    if ($#buf + 1 <= $self->{ byte_ptr } && 0 < $self->{ bit_ptr }) {
        print "*** ERROR : byte pointer is $self->{ byte_ptr } ***\n";
    }
}

sub GetByte {
    my $self = shift;
    
    if (0 != $self->{ bit_ptr }) {
        my $skip = 8 - $self->{ bit_ptr };
        print "*** WARNING : skip $skip bits ***\n";
        $self->{ bit_ptr  }  = 0;
        $self->{ byte_ptr } += 1;
    }
    
    my $rbuf = $self->{ ref_buf }; # reference to array
    my @buf  = @$rbuf;
    
    my $result = $buf[$self->{ byte_ptr }];
    $self->{ byte_ptr } += 1;

    return $result;
}

sub PeekByte {
    my $self = shift;
    
    if (0 != $self->{ bit_ptr }) {
        print "*** ERROR : 0 != bit pointer ***\n";
        return 0; # TBD
    }
    
    my $rbuf = $self->{ ref_buf }; # reference to array
    my @buf  = @$rbuf;
    return $buf[$self->{ byte_ptr }];
}

sub GetWord {
    my $self = shift;
    
    if (0 != $self->{ bit_ptr }) {
        my $skip = 8 - $self->{ bit_ptr };
        print "*** WARNING : skip $skip bits ***\n";
        $self->{ bit_ptr  }  = 0;
        $self->{ byte_ptr } += 1;
    }
    
    my $rbuf = $self->{ ref_buf }; # reference to array
    my @buf  = @$rbuf;

    my $result = ($buf[$self->{ byte_ptr }] << 8) + $buf[$self->{ byte_ptr } + 1];
    $self->{ byte_ptr } += 2;

    return $result;
}

sub GetDWord {
    my $self = shift;
    
    if (0 != $self->{ bit_ptr }) {
        my $skip = 8 - $self->{ bit_ptr };
        print "*** WARNING : skip $skip bits ***\n";
        $self->{ bit_ptr  }  = 0;
        $self->{ byte_ptr } += 1;
    }
    
    my $rbuf = $self->{ ref_buf }; # reference to array
    my @buf  = @$rbuf;

    my $ptr = $self->{ byte_ptr };
    my $result =
        ($buf[$ptr + 0] << 24) +
        ($buf[$ptr + 1] << 16) +
        ($buf[$ptr + 2] <<  8) +
         $buf[$ptr + 3];
    $self->{ byte_ptr } += 4;
    
    return $result;
}

sub GetBytes {
    my $self   = shift;
    my $length = shift;

    if (0 != $self->{ bit_ptr }) {
        my $skip = 8 - $self->{ bit_ptr };
        print "*** WARNING : skip $skip bits ***\n";
        $self->{ bit_ptr  }  = 0;
        $self->{ byte_ptr } += 1;
    }

    my $rbuf = $self->{ ref_buf }; # reference to array
    my @buf  = @$rbuf;             # de-refernece
    
    my $ptr  = $self->{ byte_ptr };
    my @bufx = @buf[$ptr .. $ptr + $length - 1]; # partial array
    $self->{ byte_ptr } += $length;
    
    return @bufx;
}

sub Get {
    my $self = shift;
    my $bits = shift;

    my $rbuf = $self->{ ref_buf }; # reference to array
    my @buf  = @$rbuf;

    my @mask = (0x00, 0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3F, 0x7F, 0xFF);
    
    my $result = 0;
    if ($bits + $self->{ bit_ptr } <= 8) {
        my $shift_bits = 8 - ($self->{ bit_ptr } + $bits);
        $result = ($buf[$self->{ byte_ptr }] & $mask[$bits] << $shift_bits) >> $shift_bits;
        $self->Skip($bits);
    }
    else {
        my $remain_bits = 8 - $self->{ bit_ptr };
        my $shift_bits  = $bits - $remain_bits;
        $result  = ($buf[$self->{ byte_ptr }] & $mask[$remain_bits]) << $shift_bits;
        $self->{ bit_ptr  }  = 0;
        $self->{ byte_ptr } += 1;
        $result += $self->Get($shift_bits); # recurseve call
    }
    return $result;
}

sub CopyRemainBytes {
    my $self = shift;

    if (0 != $self->{ bit_ptr }) {
        my $skip = 8 - $self->{ bit_ptr };
        print "*** WARNING : skip $skip bits ***\n";
        $self->{ bit_ptr  }  = 0;
        $self->{ byte_ptr } += 1;
    }

    my $rbuf = $self->{ ref_buf }; # reference to array
    my @buf  = @$rbuf;             # de-refernece

    my $ptr = $self->{ byte_ptr };
    my @remain_buf = @buf[$ptr .. $#buf];
    
    return @remain_buf;
}

1;
