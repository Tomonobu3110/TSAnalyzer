#!/usr/bin/perl

##########################################################################
# LZMA decoder
#   Copyright (C) 2012 Tomonobu Saito All Rights Reserverd.
#   Tomonobu.Saito@gmail.com

package LZMADecoder;

use warnings;
use strict;
use Carp qw(croak);

use OutWindow;
use RangeCoderDecoder;
use BitTreeDecoder;

### inline package - Base
{
    package Base;

    use constant kNumRepDistances => 4;
    use constant kNumStates => 12;

    use constant kNumPosSlotBits => 6;
    use constant kDicLogSizeMin => 0;

    use constant kNumLenToPosStatesBits => 2;
    use constant kNumLenToPosStates => 1 << kNumLenToPosStatesBits;

    use constant kMatchMinLen => 2;

    use constant kNumAlignBits => 4;
    use constant kAlignTableSize => 1 << kNumAlignBits;
    use constant kAlignMask => (kAlignTableSize - 1);

    use constant kStartPosModelIndex => 4;
    use constant kEndPosModelIndex => 14;
    use constant kNumPosModels => kEndPosModelIndex - kStartPosModelIndex;

    use constant kNumFullDistances => 1 << (kEndPosModelIndex / 2);

    use constant kNumLitPosStatesBitsEncodingMax => 4;
    use constant kNumLitContextBitsMax => 8;

    use constant kNumPosStatesBitsMax => 4;
    use constant kNumPosStatesMax => (1 << kNumPosStatesBitsMax);
    use constant kNumPosStatesBitsEncodingMax => 4;
    use constant kNumPosStatesEncodingMax => (1 << kNumPosStatesBitsEncodingMax);

    use constant kNumLowLenBits => 3;
    use constant kNumMidLenBits => 3;
    use constant kNumHighLenBits => 8;
    use constant kNumLowLenSymbols => 1 << kNumLowLenBits;
    use constant kNumMidLenSymbols => 1 << kNumMidLenBits;
    use constant kNumLenSymbols => kNumLowLenSymbols + kNumMidLenSymbols + (1 << kNumHighLenBits);
    use constant kMatchMaxLen => kMatchMinLen + kNumLenSymbols - 1;
    
    sub StateInit {
        return 0;
    }
    
    sub StateUpdateChar {
        my $index = shift;
        if ($index <  4) { return 0; }
        if ($index < 10) { return $index - 3; }
        return $index - 6;
    }
    
    sub StateUpdateMatch {
        my $index = shift;
        return ($index < 7) ? 7 : 10;
    }
    
    sub StateUpdateRep {
        my $index = shift;
        return ($index < 7) ? 8 : 11;
    }
    
    sub StateUpdateShortRep {
        my $index = shift;
        return ($index < 7) ? 9 : 11;
    }
    
    sub StateIsCharState {
        my $index = shift;
        return $index < 7;
    }
    
    sub GetLenToPosState {
        my $len = shift;
        
        $len -= kMatchMinLen;
        if ($len < kNumLenToPosStates) {
            return $len;
        }
        return kNumLenToPosStates - 1;
    }
    
    sub Max {
        my $left  = shift;
        my $right = shift;
        
        return ($left < $right) ? $right : $left;
    }
}

### inline package - LenDecoder
{
    package LenDecoder;
    
    sub new {
        my $pkg = shift;
        
        bless {
            m_Choice       => [ (undef) x 2 ],
            m_LowCoder     => [ (undef) x Base::kNumPosStatesMax ],
            m_MidCoder     => [ (undef) x Base::kNumPosStatesMax ],
            m_HighCoder    => BitTreeDecoder->new(Base::kNumHighLenBits),
            m_NumPosStates => 0,
        }, $pkg;
    }
    
    sub Create {
        my $self         = shift;
        my $numPosStates = shift;
        
        $self->{ m_NumPosStates } = $numPosStates;
        for (my $i = 0; $i < $numPosStates; ++$i) {
            ${$self->{ m_LowCoder }}[$i] = BitTreeDecoder->new(Base::kNumLowLenBits);
            ${$self->{ m_MidCoder }}[$i] = BitTreeDecoder->new(Base::kNumMidLenBits);
        }
    }
    
    sub Init {
        my $self = shift;
        
        RangeCoderDecoder::InitBitModels($self->{ m_Choice });
        for (my $posState = 0; $posState < $self->{ m_NumPosStates }; ++$posState) {
            ${$self->{ m_LowCoder }}[$posState]->Init();
            ${$self->{ m_MidCoder }}[$posState]->Init();
        }
        $self->{ m_HighCoder }->Init();
    }
    
    sub Decode {
        my $self         = shift;
        my $rangeDecoder = shift;
        my $posState     = shift;
        
        if (0 == $rangeDecoder->DecodeBit($self->{ m_Choice }, 0)) {
            return ${$self->{ m_LowCoder }}[$posState]->Decode($rangeDecoder);
        }
        my $symbol = Base::kNumLowLenSymbols;
        if (0 == $rangeDecoder->DecodeBit($self->{ m_Choice }, 1)) {
            $symbol += ${$self->{ m_MidCoder }}[$posState]->Decode($rangeDecoder);
        } else {
            $symbol += Base::kNumMidLenSymbols + $self->{ m_HighCoder }->Decode($rangeDecoder);
        }
        
        return $symbol;
    }
}
### end of package LenDecoder ###


### inline package - LiteralDecoder
{
    package LiteralDecoder;
    
    ### inline package - Decoder2
    {
        package Decoder2;
        
        sub new {
            my $pkg = shift;
            
            bless {
                m_Decoders => [ (undef) x 0x300 ],
            }, $pkg;
        }
        
        sub Init() {
            my $self = shift;
            RangeCoderDecoder::InitBitModels($self->{ m_Decoders });
        }
        
        sub DecodeNormal {
            my $self         = shift;
            my $rangeDecoder = shift;
            
            my $symbol = 1;
            do {
                #printf "Decoders 0x%x Symbol 0x%x\n", ${$self->{ m_Decoders }}[$symbol], $symbol;
                $symbol = ($symbol << 1) | $rangeDecoder->DecodeBit($self->{ m_Decoders }, $symbol);
            } while ($symbol < 0x100);
            
            #printf "DecodeNormal 0x%x\n", $symbol;
            
            return $symbol & 0xFF; # byte
        }
        
        sub DecodeWithMatchByte {
            use integer; # for logic shift (>>)
            
            my $self         = shift;
            my $rangeDecoder = shift;
            my $matchByte    = shift;
            
            my $symbol = 1;
            do {
                my $matchBit = ($matchByte >> 7) & 1;
                $matchByte = $matchByte << 1;
                my $bit = $rangeDecoder->DecodeBit($self->{ m_Decoders }, ((1 + $matchBit) << 8) + $symbol);
                $symbol = ($symbol << 1) | $bit;
                if ($matchBit != $bit) {
                    while ($symbol < 0x100) {
                        $symbol = ($symbol << 1) | $rangeDecoder->DecodeBit($self->{ m_Decoders }, $symbol);
                    }
                    #printf "DecodeWithMatchByte 0x%x\n", $symbol;
                    return $symbol & 0xFF; # break
                }
            } while ($symbol < 0x100);
            
            #printf "DecodeWithMatchByte 0x%x\n", $symbol;

            return $symbol & 0xFF; # byte
        }
    }
    ### end of package Decoder2 ###
    
    sub new {
        my $pkg = shift;
        
        bless {
            m_Coders      => undef,
            m_NumPrevBits => undef,
            m_NumPosBits  => undef,
            m_PosMask     => undef,
        }, $pkg;
    }
    
    sub Create {
        my $self        = shift;
        my $numPosBits  = shift;
        my $numPrevBits = shift;
        
        if (defined($self->{ m_Coders })             &&
            $self->{ m_NumPrevBits } == $numPrevBits &&
            $self->{ m_NumPosBits  } == $numPosBits) {
            return;
        }
        
        $self->{ m_NumPosBits  } = $numPosBits;
        $self->{ m_PosMask     } = (1 << $numPosBits) - 1;
        $self->{ m_NumPrevBits } = $numPrevBits;
        my $numStates = 1 << ($self->{ m_NumPrevBits } + $self->{ m_NumPosBits});
        
        $self->{ m_Coders } = [ (undef) x $numStates ];
        for (my $i = 0; $i < $numStates; ++$i) {
            ${$self->{ m_Coders }}[$i] = Decoder2->new();
        }
    }

    sub Init {
        my $self = shift;
        
        my $numStates = 1 << ($self->{ m_NumPrevBits } + $self->{ m_NumPosBits});
        for (my $i = 0; $i < $numStates; ++$i) {
            ${$self->{ m_Coders }}[$i]->Init();
        }
    }
    
    sub GetDecoder {
        use integer; # for logic shift (>>)
        
        my $self     = shift;
        my $pos      = shift;
        my $prevByte = shift;

        my $idx = 
            (($pos & $self->{ m_PosMask }) << $self->{ m_NumPrevBits }) +
            (($prevByte & 0xFF) >> (8 - $self->{ m_NumPrevBits }));
        return ${$self->{ m_Coders }}[$idx];
    }
}
### end of package LiteralDecoder ###

sub new {
    my $pkg = shift;
    
    my $hash = {
        m_OutWindow           => OutWindow->new(),
        m_RangeDecoder        => RangeCoderDecoder->new(),
        m_IsMatchDecoders     => [ (undef) x (Base::kNumStates << Base::kNumPosStatesBitsMax) ],
        m_IsRepDecoders       => [ (undef) x Base::kNumStates ],
        m_IsRepG0Decoders     => [ (undef) x Base::kNumStates ],
        m_IsRepG1Decoders     => [ (undef) x Base::kNumStates ],
        m_IsRepG2Decoders     => [ (undef) x Base::kNumStates ],
        m_IsRep0LongDecoders  => [ (undef) x (Base::kNumStates << Base::kNumPosStatesBitsMax) ],
        m_PosSlotDecoder      => [ (undef) x Base::kNumLenToPosStates ],
        m_PosDecoders         => [ (undef) x (Base::kNumFullDistances - Base::kEndPosModelIndex) ],
        m_PosAlignDecoder     => BitTreeDecoder->new(Base::kNumAlignBits),
        m_LenDecoder          => LenDecoder->new(),
        m_RepLenDecoder       => LenDecoder->new(),
        m_LiteralDecoder      => LiteralDecoder->new(),
        m_DictionarySize      => -1,
        m_DictionarySizeCheck => -1,
        m_PosStateMask        => undef,
    };
    
    for (my $i = 0; $i < Base::kNumLenToPosStates; ++$i) {
        ${$hash->{ m_PosSlotDecoder }}[$i] = BitTreeDecoder->new(Base::kNumPosSlotBits);
    }

    bless $hash, $pkg;
}

sub SetDictionarySize {
    my $self           = shift;
    my $dictionarySize = shift;

    if ($dictionarySize < 0) {
        return (1 == 0); # FALSE
    }
    if ($self->{ m_DictionarySize } != $dictionarySize) {
        $self->{ m_DictionarySize } = $dictionarySize;
        $self->{ m_DictionarySizeCheck } = Base::Max($self->{ m_DictionarySize }, 1);
        $self->{ m_OutWindow }->Create(Base::Max($self->{ m_DictionarySizeCheck }, (1 << 12)));
    }
    return (1 == 1); # TRUE
}

sub SetLcLpPb {
    my $self = shift;
    my $lc   = shift;
    my $lp   = shift;
    my $pb   = shift;
    
    if ($lc > Base::kNumLitContextBitsMax ||
        $lp > 4 ||
        $pb > Base::kNumPosStatesBitsMax) {
        return (1 == 0); # FALSE
    }
    $self->{ m_LiteralDecoder }->Create($lp, $lc);
    my $numPosStates = 1 << $pb;
    $self->{ m_LenDecoder    }->Create($numPosStates);
    $self->{ m_RepLenDecoder }->Create($numPosStates);
    $self->{ m_PosStateMask  } = $numPosStates - 1;
    return (1 == 1); # TRUE
}


sub Init {
    my $self = shift;
    
    $self->{ m_OutWindow }->Init(0 == 1); # FALSE
    
    RangeCoderDecoder::InitBitModels($self->{ m_IsMatchDecoders });
    RangeCoderDecoder::InitBitModels($self->{ m_IsRep0LongDecoders });
    RangeCoderDecoder::InitBitModels($self->{ m_IsRepDecoders });
    RangeCoderDecoder::InitBitModels($self->{ m_IsRepG0Decoders });
    RangeCoderDecoder::InitBitModels($self->{ m_IsRepG1Decoders });
    RangeCoderDecoder::InitBitModels($self->{ m_IsRepG2Decoders });
    RangeCoderDecoder::InitBitModels($self->{ m_PosDecoders });

    $self->{ m_LiteralDecoder }->Init();
    for (my $i = 0 ; $i < Base::kNumLenToPosStates; ++$i) {
        ${$self->{ m_PosSlotDecoder }}[$i]->Init();
    }
    $self->{ m_LenDecoder      }->Init();
    $self->{ m_RepLenDecoder   }->Init();
    $self->{ m_PosAlignDecoder }->Init();
    $self->{ m_RangeDecoder    }->Init();
}

sub Code {
    use integer; # for logic shift (>>)
    
    my $self      = shift;
    my $inStream  = shift; # reference to array
    my $outStream = shift; # reference to array
    my $outSize   = shift;

    $self->{ m_RangeDecoder }->SetStream($inStream);
    $self->{ m_OutWindow    }->SetStream($outStream);
    $self->Init();
    
    my $state = Base::StateInit();
    my $rep0  = 0;
    my $rep1  = 0;
    my $rep2  = 0;
    my $rep3  = 0;

    my $nowPos64 = 0;
    my $prevByte = 0;
    while ($outSize < 0 || $nowPos64 < $outSize) {
        #printf "outsize %d nowPos64 %d\n", $outSize, $nowPos64;
        my $posState = ($nowPos64 & $self->{ m_PosStateMask });
        #printf ">> a << state %d posState %d nowPos64 %d mask 0x%x\n", 
        #   $state, $posState, $nowPos64, $self->{ m_PosStateMask };
        if ($self->{ m_RangeDecoder }->DecodeBit($self->{ m_IsMatchDecoders }, ($state << Base::kNumPosStatesBitsMax) + $posState) == 0) {
            #printf "*** prevByte %d *** \n", $prevByte;
            my $decoder2 = $self->{ m_LiteralDecoder }->GetDecoder($nowPos64, $prevByte);
            if (!Base::StateIsCharState($state)) {
                $prevByte = $decoder2->DecodeWithMatchByte($self->{ m_RangeDecoder }, $self->{ m_OutWindow }->GetByte($rep0));
            } else {
                $prevByte = $decoder2->DecodeNormal($self->{ m_RangeDecoder });
            }
            #printf __LINE__ . " PutByte 0x%x\n", $prevByte;
            $self->{ m_OutWindow }->PutByte($prevByte);
            $state = Base::StateUpdateChar($state);
            ++$nowPos64;
        }
        else {
            my $len = undef;
            if ($self->{ m_RangeDecoder }->DecodeBit($self->{ m_IsRepDecoders }, $state) == 1) {
                $len = 0;
                if ($self->{ m_RangeDecoder }->DecodeBit($self->{ m_IsRepG0Decoders }, $state) == 0) {
                    if ($self->{ m_RangeDecoder }->DecodeBit($self->{ m_IsRep0LongDecoders }, ($state << Base::kNumPosStatesBitsMax) + $posState) == 0) {
                        $state = Base::StateUpdateShortRep($state);
                        $len = 1;
                    }
                }
                else {
                    my $distance = undef;
                    if ($self->{ m_RangeDecoder }->DecodeBit($self->{ m_IsRepG1Decoders }, $state) == 0) {
                        $distance = $rep1;
                    }
                    else {
                        if ($self->{ m_RangeDecoder }->DecodeBit($self->{ m_IsRepG2Decoders }, $state) == 0) {
                            $distance = $rep2;
                        }
                        else {
                            $distance = $rep3;
                            $rep3 = $rep2;
                        }
                        $rep2 = $rep1;
                    }
                    $rep1 = $rep0;
                    $rep0 = $distance;
                }
                if ($len == 0) {
                    #print "RepLenDecoder::Decode\n";
                    $len = $self->{ m_RepLenDecoder }->Decode($self->{ m_RangeDecoder }, $posState) + Base::kMatchMinLen;
                    $state = Base::StateUpdateRep($state);
                    #printf "RepLenDecoder::Decode len %d posState %d\n", $len, $posState;;
                }
            }
            else {
                $rep3 = $rep2;
                $rep2 = $rep1;
                $rep1 = $rep0;
                $len = Base::kMatchMinLen + $self->{ m_LenDecoder }->Decode($self->{ m_RangeDecoder }, $posState);
                $state = Base::StateUpdateMatch($state);
                my $posSlot = ${$self->{ m_PosSlotDecoder }}[Base::GetLenToPosState($len)]->Decode($self->{ m_RangeDecoder });
                if ($posSlot >= Base::kStartPosModelIndex) {
                    my $numDirectBits = ($posSlot >> 1) - 1;
                    $rep0 = ((2 | ($posSlot & 1)) << $numDirectBits);
                    if ($posSlot < Base::kEndPosModelIndex) {
                        $rep0 += BitTreeDecoder::ReverseDecode_static(
                            $self->{ m_PosDecoders },
                            $rep0 - $posSlot - 1,
                            $self->{ m_RangeDecoder },
                            $numDirectBits);
                    }
                    else {
                        $rep0 += ($self->{ m_RangeDecoder }->DecodeDirectBits(
                            $numDirectBits - Base::kNumAlignBits) << Base::kNumAlignBits);
                        $rep0 += $self->{ m_PosAlignDecoder }->ReverseDecode(
                            $self->{ m_RangeDecoder });
                        if ($rep0 < 0) {
                            if ($rep0 == -1) { last; } # break
                            print "FALSE at " . __LINE__ . "\n";
                            return (0 == 1); # FALSE
                        }
                    }
                }
                else {
                    $rep0 = $posSlot;
                }
            }
            #printf "rep0 %d nowPos64 %d\n", $rep0, $nowPos64;
            if ($rep0 >= $nowPos64 ||
                $rep0 >= $self->{ m_DictionarySizeCheck }) {
                print "FALSE at " . __LINE__ . "\n";
                return (0 == 1); # FALSE
            }
            $self->{ m_OutWindow }->CopyBlock($rep0, $len);
            $nowPos64 += $len;
            $prevByte = $self->{ m_OutWindow }->GetByte(0);
            #printf "+++ $prevByte %d +++\n", $prevByte;
        }
    }
    $self->{ m_OutWindow }->Flush();
    $self->{ m_OutWindow }->ReleaseStream();
    $self->{ m_RangeDecoder }->ReleaseStream();
    return (1 == 1); # TRUE
}

sub SetDecoderProperties {
    my $self       = shift;
    my $properties = shift; # reference to array
    
    my @prop = @$properties; # de-reference
    if (@prop < 5) { return (0 == 1); } # FALSE

    my $val       = $prop[0] & 0xFF;
    my $lc        = $val % 9;
    my $remainder = $val / 9;
    my $lp        = $remainder % 5;
    my $pb        = $remainder / 5;
    my $dict_size = 0;
    for (my $i = 0; $i < 4; ++$i) {
        $dict_size += ($prop[1 + $i] & 0xFF) << ($i * 8);
    }
    return 
        $self->SetLcLpPb($lc, $lp, $pb) &&
        $self->SetDictionarySize($dict_size);
}

1;
