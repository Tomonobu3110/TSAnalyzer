#!/usr/bin/perl

##########################################################################
# Polsat PIS(Program Information Structure)
#   Copyright 2012, Tomonobu Saito
#   Tomonobu.Saito@gmail.com

package PolsatPIS;

use warnings;
use strict;
use Carp qw(croak);

# for LZMA decode
use OutWindow;
use RangeCoderDecoder;
use BitTreeDecoder;
use LZMADecoder;

use TSPacket;

sub new {
    my $pkg      = shift;
    my $_program = shift;
    my $_day     = shift;
    my $_lang    = shift;
    my $_version = shift;
    my $_lastsec = shift;
    bless {
        program => $_program,
        day     => $_day,
        lang    => $_lang,
        version => $_version,
        lastsec => $_lastsec,
        packets => [], # array of refernce to data buffer
    }, $pkg;
}

sub IsSame {
    my $self     = shift;
    my $_program = shift;
    my $_day     = shift;
    my $_lang    = shift;
    my $_version = shift;
    
    return 
        ($self->{ program } == $_program) &&
        ($self->{ day     } == $_day    ) &&
        ($self->{ lang    } == $_lang   ) &&
        ($self->{ version } == $_version);
}

sub IsComplete {
    my $self = shift;
    my @packets = @{$self->{ packets }};
    for (my $i = 0; $i <= $self->{ lastsec }; ++$i) {
        unless (defined($packets[$i])) {
            return (0 == 1); # FALSE
        }
    }
    return (1 == 1); # TRUE
}

sub SetPacket {
    my $self    = shift;
    my $section = shift;
    my $rpacket = shift; # refernece to packet(array)
    
    # copy
    @{$self->{ packets }}[$section] = $rpacket;
}

sub GetBuffer {
    my $self = shift;
    
    # pre-condition (must be completed)
    unless ($self->IsComplete()) {
        return 0;
    }
    
    # join all buffer.
    my @buffer;
    my @packets = @{$self->{ packets }};
    for (my $i = 0; $i <= $self->{ lastsec }; ++$i) {
        unless (defined($packets[$i])) {
            return (0 == 1); # just in case.
        }
        my $ref_packet = $packets[$i];
        push(@buffer, @$ref_packet); # de-refernece
    }
    
    return @buffer; # array
}

sub WriteBinaryFile {
    my $self = shift;
    my @buff = $self->GetBuffer();

#    print "===== DUMP PIS BEGIN =====\n";
#    my $i = 0;
#    foreach my $b (@buff) {
#       printf "0x%02X ", $b;
#       if (0 == (($i + 1) % 8)) { 
#           print "\n";
#       }
#       $i += 1;
#    }
#    print "\n===== DUMP PIS END =======\n";

    my $filename = 
        "PolsatPIS_" . 
        $self->{ program } . "_" .
        $self->{ day     } . "_" .
        $self->{ lang    } . "_" .
        $self->{ version } . ".lzma";
    if (open(OUT, "> $filename")) {
        binmode(OUT);
        syswrite OUT, pack("C*", @buff), $#buff + 1;
        close(OUT);
    }
    return $filename;
}

sub ParseAndDump {
    my $self = shift;
    my @buff = $self->GetBuffer();

    # properties
    my $decoder = LZMADecoder->new();
    my @props = splice(@buff, 0, 5);
    unless ($decoder->SetDecoderProperties(\@props)) {
        print "LZMA : NG (properties)\n";
        return; # exit function
    }
    
    # size
    my $outsize = 0;
    for (my $i = 0; $i < 8; ++$i) {
        $outsize |= shift(@buff) << (8 * $i);
    }
    
    # uncompress
    my @outbuf = ();
    unless ($decoder->Code(\@buff, \@outbuf, $outsize)) {
        print "LZMA : NG (code)\n";
        return; # exit function.
    }
    
    # parse
    my $pis = TSPacket->new;
    $pis->SetBuffer(\@outbuf);

    while (!$pis->EOF()) {
        printf "  event_id       0x%04X\n", $pis->GetWord();
        printf "  time_beginning %02x:%02x:%02x\n", $pis->GetByte(), $pis->GetByte(), $pis->GetByte();
        printf "  duration       %02x:%02x:%02x\n", $pis->GetByte(), $pis->GetByte(), $pis->GetByte();
        printf "  program_type_1 %d\n",     $pis->Get(4);
        printf "  program_type_2 %d\n",     $pis->Get(4);
        my $title_len = $pis->GetByte();
        printf "  title_length   %d\n", $title_len;
        printf "  title_char     "; dump_string($pis->GetBytes($title_len));

        # descriptor
        my $desc_len = $pis->GetWord();
        printf "  descriptor_len %d\n", $desc_len;
        print  "  {\n";

        # descriptor loop
        $pis->SetDescriptorLength($desc_len);
        while (0 < $pis->GetRemainBytesOfDescriptor()) {
            my $tag = $pis->GetByte();
            my $len = $pis->GetByte();
            my @buf = $pis->GetBytes($len);
            printf "    tag:0x%02X len:%d\n", $tag, $len;

            my $desc = TSPacket->new;
            $desc->SetBuffer(\@buf);
            $desc->SetDescriptorLength($len);
            
            if    (0xbe == $tag) { dump_descriptor_0xbe($desc); }
            elsif (0xbf == $tag) { dump_descriptor_0xbf($desc); }
            elsif (0xa1 == $tag) { dump_descriptor_0xa1($desc); }
            elsif (0xd8 == $tag) { dump_descriptor_0xd8($desc); }
            else {
                printf "      unknown tag 0x%02X\n", $tag;
            }
        }
        print "  }\n";
    }
}

sub dump_string {
    foreach my $c (@_) {
        if (0x20 <= $c && $c <= 0x7F) {
           print chr($c);
        } else {
           printf "[%02X]", $c;
        }
    }
    print "\n";
}

sub dump_descriptor_0xbe {
    my $desc = shift;
    printf "      (epg_extended_info_descriptor)\n";
    printf "      descriptor_number      %d\n", $desc->Get(4);
    printf "      last_descriptor_number %d\n", $desc->Get(4);
    my $length = $desc->GetRemainBytesOfDescriptor();
    printf "      text_char (%d) ", $length;
    dump_string($desc->GetBytes($length));
}

sub dump_descriptor_0xbf {
    my $desc = shift;
    printf "      (parental_rating_descriptor)\n";
    printf "      rating %d\n", $desc->GetByte();
}

sub dump_descriptor_0xa1 {
    my $desc = shift;
    printf "      (simple_vod_descriptor)\n";
    printf "      svod_id                    0x%04X\n", $desc->GetWord();
    printf "      recording_start_time(date) 0x%08x\n", mjd($desc->GetWord());
    printf "      recording_start_time(time) %02x:%02x:%02x\n", 
        $desc->GetByte(), $desc->GetByte(), $desc->GetByte();
    printf "      recording_duration         %02x:%02x:%02x\n", 
        $desc->GetByte(), $desc->GetByte(), $desc->GetByte();
    printf "      quota_size                 %d\n", $desc->GetByte();
    printf "      expiry_date(date)          0x%08x\n", mjd($desc->GetWord());
    printf "      expiry_date(time)          %02x:%02x:%02x\n", 
        $desc->GetByte(), $desc->GetByte(), $desc->GetByte();
    printf "      last_broadcast_date(date)  0x%08x\n", mjd($desc->GetWord());
    printf "      last_broadcast_date(time)  %02x:%02x:%02x\n", 
        $desc->GetByte(), $desc->GetByte(), $desc->GetByte();
}

sub dump_descriptor_0xd8 {
    my $desc = shift;
    printf "      (cp_content_protection_descriptor)\n";
    printf "      hdd_content_protection_flag   %d\n", $desc->Get(1);
    printf "      reserved                      %d\n", $desc->Get(7);
    printf "      analogue_outputs_protect_flag %d\n", $desc->Get(1);
    printf "      cgms-a                        %d\n", $desc->Get(2);
    printf "      reserved                      %d\n", $desc->Get(5);
}

sub mjd {
    my $mjd = shift;
    
    my $y0 = int(($mjd - 15078.2) / 365.25);
    my $m0 = int(($mjd - 14956.1 - int($y0 * 365.25)) / 30.6001);
    my $d  = $mjd - 14956 - int($y0 * 365.25) - int($m0 * 30.6001);
    my $k  = (14 == $m0 || 15 == $m0) ? 1 : 0;
    my $y  = $y0 + $k;
    my $m  = $m0 - 1 - ($k * 12);
    
    return sprintf("%04d/%02d/%02d", $y + 1900, $m, $d);
}

1;

