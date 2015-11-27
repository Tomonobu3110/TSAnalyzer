#!/usr/bin/perl

##########################################################################
# TS Parser
#   Copyright (C) 2012 Tomonobu Saito All Rights Reserved.
#   Tomonobu.Saito@gmail.com

use strict;
use warnings;

use TSPacket;
use PacketBuffer;
use DuplicateChecker;
use PolsatPIS;

#====================================================================
# CONFIGRATION { BEGIN }
#====================================================================
my(@gen_pid_list);
push(@gen_pid_list, 0x00); # PAT
#push(@gen_pid_list, 0x10); # NIT
#push(@gen_pid_list, 0x11); # SDT, BAT
#push(@gen_pid_list, 0x12); # EIT
push(@gen_pid_list, 0x14); # TOT/TDT

my $check_version   = 1; # 0 ... no check, 1 ... check, 2 ... with log
my $check_crc32     = 1; # 0 ... no check, 1 ... check, 2 ... with log
my $check_integrity = 1; # 0 ... no check, 1 ... check
my $dump_summary    = 1; # 0 ... not show, 1 ... show
my $dump_descriptor = 1; # 0 ... not show, 1 ... show
my $dump_err_packet = 1; # 0 ... not dump, 1 ... dump
my $dump_polsat_epg = 1; # 0 ... not dump, 1 ... dump, 2 ... dump file
#====================================================================
# CONFIGRATION { END }
#====================================================================

#====================================================================
# GLOBAL VALUE { BEGIN }
#====================================================================
my $polsat_epg_pid = undef;
my @polsat_pis_list;
#====================================================================
# GLOBAL VALUE { END }
#====================================================================

# global const.
use constant numeric =>
    [ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' ];

unless (1 <= $#ARGV) {
    print "*** USAGE ***\n";
    print "ts.pl <TS FILE> <0 | NUMBER OF PACKTES TO PARSE>\n";
    exit(0);
}

main_loop($ARGV[0], $ARGV[1]);

exit(0);

##########################################################################
#
# main_loop
#
sub main_loop {
    my($file, $count) = @_;

    # open the target file.
    my $file_size = 0;
    unless (open(IN, $file)) {
        print "*** CAN'T OPEN $ARGV[0] ***\n";
        exit(1);
    } else {
        binmode(IN);
        $file_size = -s $file;
    }

    # pid list
    my(@pmt_pid_list) = ();
    my(@es_pid_list)  = ();
    my($nit_pid_from_pmt) = undef;

    # buffer for multi section table
    my(@multi_section_tables);

    my($buf);
    my(@data);
    my(@table_data);
    my(%packet_buf_list) = ();

    my(@table_list) = (); # for duplication check

    # initial pid filter.
    my @pid_list;
    push(@pid_list, @gen_pid_list);
    push(@pid_list, @pmt_pid_list);
    push(@pid_list, @es_pid_list);
    if (defined($nit_pid_from_pmt)) {
        push(@pid_list, $nit_pid_from_pmt);
    }
    if (defined($polsat_epg_pid)) {
        push(@pid_list, $polsat_epg_pid);
    }

    # read the file.
    for (my $i = 0; $i < $count || 0 == $count; ++$i) {
        my $n = sysread(IN, $buf, 188);
        if ($n != 188) {
            print "*** EOF($i packets) ***\n";
            last;
        }
        if (0 < $i && 0 == $i % 100000) {
            my $progress = (0 == $count) ?
                ($i * 18800 / $file_size) : ($i * 100 / $count);
            printf "%d packets (%.2f%%) completed.\n",
                   $i, $progress;
        }

        # get data buffer
        @data = unpack("C*", $buf);
        my $tspacket = TSPacket->new;
        $tspacket->SetBuffer(\@data);

        ################################
        # TS Packet
        ################################

        # ts header
        my %ts_header = get_ts_header($tspacket);
        dump_ts_header(%ts_header);
        if ($ts_header{ synchronization_byte } != 0x47) {
            print "*** ERROR PACKET ($i) ***\n";
            #
            # recovery mode
            #
            seek(IN, -188, 1); # rewind
            my $skip = 0;
            do {
                $n = sysread(IN, $buf, 1);
                if ($n != 1) {
                    print "*** FORCE CLOSE ***\n";
                    close(IN);
                    exit;
                }
                $skip += 1;
            } while (0x47 != unpack("C1", $buf));
            # back 1 byte
            seek(IN, -1, 1); # back 1 byte from current position.
            printf "*** SKIP %d bytes ***\n", $skip - 1;
            next; # continue
        }
        my $pid = $ts_header{ pid };
        my $idx = $ts_header{ continuity_index };
        my $adp = $ts_header{ adaptation_field_control };

        # filtering by PID
        my $target_packet = 0;
        foreach my $p (@pid_list) {
            if ($p == $pid) {
                $target_packet = 1;
                last; # break
            }
        }
        if (0 == $target_packet) {
            printf "pid mismatch 0x%04X\n", $pid;
            next; # continue
        }

        # for debug...
        #printf "===== TS packet ";
        #$tspacket->Dump();
        #dump_ts_header(%ts_header);

        # query PacketBuffer by PID
        my $packet_buf = $packet_buf_list{ $pid };
        unless (defined($packet_buf)) {
            if (1 == $ts_header{ payload_unit_start_indicator }) {
                # ***** VERY FIRST PACKET FOR THE PID. *****
                #                    |<------- payload ------->|
                # +------------------+---+-----------+---------+
                # |(adaptation field)| N | xxxxxxxxx | new buf |
                # +------------------+---+-----------+---------+
                #                    ^   |<--- N --->|
                #                    start_idx = pointer_field
                $packet_buf = PacketBuffer->new;
                my $start_idx     = get_start_index_of_payload($adp, \@data);
                my $pointer_field = $data[$start_idx]; # get 'N'
                my $start_point   = $start_idx + 1 + $pointer_field;
                my @datax = @data[$start_point..$#data];
                $packet_buf->Init($pid, $idx, \@datax);
                $packet_buf_list{ $pid } = $packet_buf;
            }
            next; # continue
        }
        else {
            if ($packet_buf->GetIndex() == $idx) {
                # same index, just ignore.
                next; # continue
            }
            elsif (2 == $adp) {
                # only adaptation field, just ignore.
                next; # continue
            }
            elsif ((($packet_buf->GetIndex() + 1) % 16) != $idx) {
                # reset buffer
                $packet_buf_list{ $pid } = undef;
                next; # continue
            }
            else {
                if (0 == $ts_header{ payload_unit_start_indicator }) {
                    my $start_idx = get_start_index_of_payload($adp, \@data);
                    my @datax = @data[$start_idx..$#data];
                    $packet_buf->Add($idx, \@datax);
                    next; # continue
                } else {
                    # GET BUFFER OF PAYLOAD/ADDAPTATION FIELD
                    #                    |<-------- payload --------->|
                    # +------------------+---+-------------+----------+
                    # |(adaptation field)| N | current buf | next buf |
                    # +------------------+---+-------------+----------+
                    #                      ^ |<---- N ---->|
                    #                      start_idx = pointer_field
                    my $start_idx = get_start_index_of_payload($adp, \@data);
                    my $pointer_field = $data[$start_idx]; # get 'N'
                    my $next_start_point  = $start_idx + 1 + $pointer_field;
                    my $current_end_point = $next_start_point - 1;
                    # >>> addition to current buffer
                    if (0 < $pointer_field) {
                        my @datac = @data[($start_idx + 1)..$current_end_point];
                        $packet_buf->Add($idx, \@datac);
                    }
                    @table_data = $packet_buf->GetBuffer();
                    # >>> initialization of next buffer
                    my @datax = @data[$next_start_point..$#data];
                    $packet_buf->Init($pid, $idx, \@datax);
                    # go SI/PSI
                }
            }
        }

        ################################
        # Payload of TS Packet
        ################################

        my $table = TSPacket->new;
        $table->SetBuffer(\@table_data);

        ################################
        # SI/PSI
        ################################

        until ($table->EOF() || 0xff == $table->PeekByte()) {

            ################################
            # private section header
            ################################
            my %private_sec = get_private_section($table);
            #printf "===== Section ";
            #$table->Dump();
            #dump_private_section(%private_sec);
            if (0 == $private_sec{ status }) {
                print "*** SECTION LENGTH ERROR ($i) ***\n";
                if (0 < $dump_err_packet) {
                    printf "===== Section ";
                    $table->Dump();
                    dump_private_section(%private_sec);
                }
                $table->SkipToNextSection();
                next; # continue
            }

            ################################
            # Integrity check
            ################################

            my $table_id       = $private_sec{ table_id };
            my $section_syntax = $private_sec{ section_syntax_indicator };

            if (0 < $check_integrity) {
                # PID vs section_syntax_indicator
                if (0 == $section_syntax &&
                    (0x10 == $pid ||
                     0x11 == $pid ||
                     0x12 == $pid)) {
                    printf "*** INTEGRITY CHECK FAILED (%d) PID 0x%04X SYNTAX %d\n",
                           $i, $pid, $section_syntax;
                    if (0 < $dump_err_packet) {
                        printf "===== Section ";
                        $table->Dump();
                        dump_private_section(%private_sec);
                    }
                    $table->SkipToNextSection();
                    next; # continue
                }
                # PID vs table_id
            }

            ################################
            # CRC32
            ################################
            if (0 < $check_crc32) {
                if (1 == $private_sec{ section_syntax_indicator }) {
                    #$table->Dump();
                    my @body    = $table->GetBody();
                    my @payload = @body[0..($#body - 4)];
                    my @crc32   = @body[($#body - 3)..$#body];
                    my $crc32   = ($crc32[0] << 24) +
                                  ($crc32[1] << 16) +
                                  ($crc32[2] <<  8) +
                                  ($crc32[3] <<  0);
                    my $crc32_of_payload = CRC32(\@payload);
                    if (1 < $check_crc32) {
                        printf "CRC32 field  : 0x%08x\n", $crc32_of_payload;
                        printf "CRC32 calced : 0x%08x\n", $crc32;
                    }
                    if ($crc32 != $crc32_of_payload) {
                        print "*** CRC32 ERROR PACKET ($i) ***\n";
                        if (0 < $dump_err_packet) {
                            printf "===== Section ";
                            $table->Dump();
                            dump_private_section(%private_sec);
                        }
                        $table->SkipToNextSection();
                        next; # continue
                    }
                }
                else {
                    if (1 < $check_crc32) {
                        printf "NO CRC32 (section_syntax_indicator = 0)\n";
                    }
                }
            }

            ################################
            # Duplication check
            ################################

            my $table_id_extension = $private_sec{ table_extension_id };
            my $section_number     = $private_sec{ section_number };
            my $version_number     = $private_sec{ version_number };

            if (0 < $check_version && 1 == $section_syntax) {
                my $found_item = undef;
                foreach my $item (@table_list) {
                    if ($item->Equal($table_id, $table_id_extension, $section_number)) {
                        $found_item = $item;
                        last; # break
                    }
                }
                if (defined($found_item)) {
                    if ($found_item->GetNextVersion() == $version_number) {
                        if (1 < $check_version) {
                            printf "*** new version %d (0x%02X,0x%04X,0x%02X,v%d) ***\n",
                                $i,
                                $table_id,
                                $table_id_extension,
                                $section_number,
                                $version_number;
                        }
                        $found_item->SetVersion($version_number);
                    } else {
                        if (1 < $check_version) {
                            printf "*** same or old table %d (0x%02X,0x%04X,0x%02X,v%d) ***\n",
                                $i,
                                $table_id,
                                $table_id_extension,
                                $section_number,
                                $version_number;
                        }
                        $table->SkipToNextSection();
                        next; # continue
                    }
                } else {
                    if (1 < $check_version) {
                        printf "*** new table %d (0x%02X,0x%04X,0x%02X,v%d) ***\n",
                            $i,
                            $table_id,
                            $table_id_extension,
                            $section_number,
                            $version_number;
                    }
                    my $new_item = DuplicateChecker->new;
                    $new_item->Set($table_id,
                                   $table_id_extension,
                                   $section_number,
                                   $version_number);
                    push(@table_list, $new_item);
                }
            }

            ################################
            # Table parsing
            ################################

            print "pid $pid\n";

            # PAT
            if ($pid == 0) {
                dump_table_found("PAT", $pid, $i, \%private_sec);
                my %pat = get_pat($table, %private_sec);
                dump_pat(%pat);
                @pmt_pid_list     = get_pid_list_from_pat(%pat);
                $nit_pid_from_pmt = get_nit_pid_from_pat(%pat);
                # update pid list.
                @pid_list = ();
                push(@pid_list, @gen_pid_list);
                push(@pid_list, @pmt_pid_list);
                push(@pid_list, @es_pid_list);
                if (defined($nit_pid_from_pmt)) {
                    push(@pid_list, $nit_pid_from_pmt);
                }
                if (defined($polsat_epg_pid)) {
                    push(@pid_list, $polsat_epg_pid);
                }
                $table->SkipToNextSection();
                next; # continue
            }

            # PMT
            foreach my $pmt_pid (@pmt_pid_list) {
                if ($pmt_pid == $pid) {
                    dump_table_found("PMT", $pid, $i, \%private_sec);
                    #dump_ts_header(%ts_header);
                    #dump_private_section(%private_sec);
                    #$table->Dump();
                    my %pmt = get_pmt($table, %private_sec);
                    dump_pmt(%pmt);
                    last; # break
                }
            }

            # NIT
            if (0x10 == $pid ||
                (defined($nit_pid_from_pmt) && $nit_pid_from_pmt == $pid)) {
                my $name = (0x40 == $table_id ? "NITa" : "NITo");
                dump_table_found($name, $pid, $i, \%private_sec);
                #dump_ts_header(%ts_header);
                #$table->Dump();
                my %nit = get_nit($table, %private_sec);
                dump_nit(%nit);
                # update pid list.
                @pid_list = ();
                push(@pid_list, @gen_pid_list);
                push(@pid_list, @pmt_pid_list);
                push(@pid_list, @es_pid_list);
                if (defined($nit_pid_from_pmt)) {
                    push(@pid_list, $nit_pid_from_pmt);
                }
                if (defined($polsat_epg_pid)) {
                    push(@pid_list, $polsat_epg_pid);
                }
                $table->SkipToNextSection();
                next; # continue
            }

            # BAT
            if (0x11 == $pid && 0x4A == $table_id) {
                dump_table_found("BAT", $pid, $i, \%private_sec);
                my %bat = get_bat($table, %private_sec);
                dump_bat(%bat);
                # update pid list.
                @pid_list = ();
                push(@pid_list, @gen_pid_list);
                push(@pid_list, @pmt_pid_list);
                push(@pid_list, @es_pid_list);
                if (defined($nit_pid_from_pmt)) {
                    push(@pid_list, $nit_pid_from_pmt);
                }
                if (defined($polsat_epg_pid)) {
                    push(@pid_list, $polsat_epg_pid);
                }
                $table->SkipToNextSection();
                next; # continue
            }

            # SDT
            if (0x11 == $pid && (0x42 == $table_id || 0x46 == $table_id)) {
                my $name = (0x42 == $table_id ? "SDTa" : "SDTo");
                dump_table_found($name, $pid, $i, \%private_sec);
                #dump_ts_header(%ts_header);
                #dump_private_section(%private_sec);
                #$table->Dump();
                my %sdt = get_sdt($table, %private_sec);
                dump_sdt(%sdt);
                $table->SkipToNextSection();
                next; # continue
            }

            # EIT
            if (0x12 == $pid) {
                my $name = "EIT";
                if    (0x4e == $table_id) { $name = "EITpf(a)"; }
                elsif (0x4f == $table_id) { $name = "EITpf(o)"; }
                elsif (0x50 <= $table_id &&
                       $table_id <= 0x5f) { $name = "EITsch(a)"; }
                elsif (0x60 <= $table_id &&
                       $table_id <= 0x6f) { $name = "EITsch(o)"; }
                dump_table_found($name, $pid, $i, \%private_sec);
                #dump_private_section(%private_sec);
                #$table->Dump();
                my %eit = get_eit($table, %private_sec);
                dump_eit(%eit);
                $table->SkipToNextSection();
                next; # continue
            }

            # TOT/TDT
            if (0x14 == $pid) {
                dump_table_found("TOT/TDT", $pid, $i, \%private_sec);
                my %tot_tdt = get_tot_tdt($table, %private_sec);
                dump_tot_tdt(%tot_tdt);
                $table->SkipToNextSection();
                next; # continue
            }

            # CLT (for Polsat)
            if (0xfa == $table_id) {
                dump_table_found("CLT", $pid, $i, \%private_sec);
                my %clt = get_clt($table, %private_sec);
                dump_clt(%clt);
                $table->SkipToNextSection();
                next; # continue
            }

            # PDT (for Polsat)
            if (0xfb == $table_id) {
                dump_table_found("PDT", $pid, $i, \%private_sec);
                my %pdt = get_pdt($table, %private_sec);
                dump_pdt(%pdt);
                $table->SkipToNextSection();
                next; # continue
            }

            $table->SkipToNextSection();
        }
    }

    # close the file.
    close(IN);
}

##########################################################################
#
# PARSER
#
##########################################################################

#=========================================================================
# TS header
#=========================================================================
sub get_ts_header {
    my $p = shift;
    return (
        synchronization_byte         => $p->GetByte(),
        transport_error_indicator    => $p->Get( 1),
        payload_unit_start_indicator => $p->Get( 1),
        transport_priority           => $p->Get( 1),
        pid                          => $p->Get(13),
        transport_scrambling_control => $p->Get( 2),
        adaptation_field_control     => $p->Get( 2),
        continuity_index             => $p->Get( 4)
    );
}

#=========================================================================
# Private Section
#=========================================================================
sub get_private_section {
    my $p = shift;
    my $ok = $p->SetHeadPointer();
    if (!$ok) {
        return { status => 0 }; # no name hash.
    }
    my %section_head = (
        table_id                 => $p->GetByte(),
        section_syntax_indicator => $p->Get( 1),
        reserved_0               => $p->Get( 1),
        reserved_1               => $p->Get( 2),
        section_length           => $p->Get(12),
    );

    if (1 == $section_head{ section_syntax_indicator }) {
        my %section_ext = (
            table_extension_id       => $p->GetWord(),
            reserved_2               => $p->Get( 2),
            version_number           => $p->Get( 5),
            current_next_indicator   => $p->Get( 1),
            section_number           => $p->GetByte(),
            last_section_number      => $p->GetByte()
        );

        # 5 ... byte length from table_extension_id to last_section_number
        # 4 ... byte length of CRC32
        $section_head{ payload_length } = $section_head{ section_length } - 5 - 4;
        $p->SetSectionLength   ($section_head{ payload_length });
        $ok = $p->SetBodyLength($section_head{ section_length } - 5);
        $section_head{ status } = $ok ? 1 : 0;

        my %section = (%section_head, %section_ext); # join hash tables
        return %section;
    }

    else {
        my %section_ext = (
            table_extension_id       => 0,
            version_number           => 0,
            current_next_indicator   => 0,
            section_number           => 0,
            last_section_number      => 0
        );
        # << CAUTION >>
        # payload_length may contain CRC32.
        # - TDT does not have CRC32.
        # - TOT have CRC32. This case, payload_length contains CRC32.
        $section_head{ payload_length } = $section_head{ section_length };
        $p->SetSectionLength   ($section_head{ payload_length });
        $ok = $p->SetBodyLength($section_head{ payload_length });
        $section_head{ status } = $ok ? 1 : 0;

        my %section = (%section_head, %section_ext); # join hash tables
        return %section;
    }
}

#=========================================================================
# descriptor
#=========================================================================
sub get_descriptor {
    my $p      = shift;
    my $length = shift; # total length of descriptor

    $p->SetDescriptorLength($length);

    my @descriptor_list = ();
    while (0 < $p->GetRemainBytesOfDescriptor()) {
        my %descriptor = (
            descriptor_tag    => $p->GetByte(),
            descriptor_length => $p->GetByte(),
        );
        my @desc_buf = $p->GetBytes($descriptor{ descriptor_length });
        $descriptor{ desc_buf } = \@desc_buf;
        push(@descriptor_list, \%descriptor);

#       printf "  - desc : tag 0x%02x len %d\n",
#           $descriptor{ descriptor_tag },
#           $descriptor{ descriptor_length };
    }

    return \@descriptor_list; # returns reference to the list.
}

sub get_descriptor_by_num {
    my $p     = shift;
    my $count = shift; # number of descriptor

    my @descriptor_list = ();
    while (0 < $count) {
        my %descriptor = (
            descriptor_tag    => $p->GetByte(),
            descriptor_length => $p->GetByte(),
        );
        my @desc_buf = $p->GetBytes($descriptor{ descriptor_length });
        $descriptor{ desc_buf } = \@desc_buf;
        push(@descriptor_list, \%descriptor);

#       printf "  - desc : tag 0x%02x len %d\n",
#           $descriptor{ descriptor_tag },
#           $descriptor{ descriptor_length };
        --$count;
    }

    return \@descriptor_list; # returns reference to the list.
}

#=========================================================================
# PAT
#=========================================================================
sub get_pat {
    my $p   = shift;
    my %pat = @_;

    # Program loop
    my @program_list = ();
    while (0 < $p->GetRemainBytesOfSection()) {
        my %program = (
            program_number => $p->GetWord(),
            reserved       => $p->Get(3),
            PID            => $p->Get(13),
        );
        push(@program_list, \%program); # add reference to hash.
    }

    $pat{ program_list } = \@program_list; # set reference to array.

    return %pat;
}

#=========================================================================
# PMT
#=========================================================================
sub get_pmt {
    my $p   = shift;
    my %pmt = @_;

    $pmt{ reserved_3          } = $p->Get( 3);
    $pmt{ PCR_PID             } = $p->Get(13);
    $pmt{ reserved_4          } = $p->Get( 4);
    $pmt{ program_info_length } = $p->Get(12);
    $pmt{ descriptor_program  } = get_descriptor($p, $pmt{ program_info_length });

    # ES loop
    my @es_list = ();
    while (0 < $p->GetRemainBytesOfSection()) {
        my %es = (
            stream_type       => $p->GetByte(),
            reserved_1        => $p->Get( 3),
            elementary_PID    => $p->Get(13),
            reserved_2        => $p->Get( 4),
            descriptor_length => $p->Get(12)
        );
        $es{ descriptor } = get_descriptor($p, $es{ descriptor_length });
        push(@es_list, \%es); # add reference to hash.

        if (0 < $dump_summary) {
            printf "#%d pgm 0x%04X(%d) type 0x%02X ES_PID 0x%04X\n",
                $#es_list + 1,
                $pmt{ table_extension_id },
                $pmt{ table_extension_id },
                $es{ stream_type },
                $es{ elementary_PID };
        }
    }

    $pmt{ es_list } = \@es_list; # set refernece to array.

    return %pmt;
}

#=========================================================================
# NIT
#=========================================================================
sub get_nit {
    my $p   = shift;
    my %nit = @_;

    $nit{ reserved_3        } = $p->Get( 4);
    $nit{ descriptor_length } = $p->Get(12);
    $nit{ descriptor        } = get_descriptor($p, $nit{ descriptor_length });

    $nit{ reserved_4 } = $p->Get(4);
    $nit{ tarnsport_stream_loop_length } = $p->Get(12);

    # Network loop
    my @network_list = ();
    while (0 < $p->GetRemainBytesOfSection()) {
        my %network = (
            transport_stream_id => $p->GetWord(),
            original_network_id => $p->GetWord(),
            reserved            => $p->Get( 4),
            descriptor_length   => $p->Get(12)
        );
        $network{ descriptor } =
            get_descriptor($p, $network{ descriptor_length });
        push(@network_list, \%network); # add reference to Hash.

        if (0 < $dump_summary) {
            printf "#%d tsid 0x%04x onid 0x%04x\n",
                $#network_list + 1,
                $network{ transport_stream_id },
                $network{ original_network_id };
        }
    }
    $nit{ network_list } = \@network_list;

    return %nit;
}

#=========================================================================
# BAT
#=========================================================================
sub get_bat {
    my $p   = shift;
    my %bat = @_;

    $bat{ reserved_3        } = $p->Get( 4);
    $bat{ descriptor_length } = $p->Get(12);
    $bat{ descriptor        } = get_descriptor($p, $bat{ descriptor_length });

    $bat{ reserved_4 } = $p->Get(4);
    $bat{ tarnsport_stream_loop_length } = $p->Get(12);

    # TS loop
    my @ts_list = ();
    while (0 < $p->GetRemainBytesOfSection()) {
        my %ts = (
            transport_stream_id => $p->GetWord(),
            original_network_id => $p->GetWord(),
            reserved            => $p->Get( 4),
            descriptor_length   => $p->Get(12)
        );
        $ts{ descriptor } =
            get_descriptor($p, $ts{ descriptor_length });
        push(@ts_list, \%ts); # add reference to Hash.

        if (0 < $dump_summary) {
            printf "#%d tsid 0x%04x onid 0x%04x\n",
                $#ts_list + 1,
                $ts{ transport_stream_id },
                $ts{ original_network_id };
        }
    }
    $bat{ ts_list } = \@ts_list;

    return %bat;
}

#=========================================================================
# SDT
#=========================================================================
sub get_sdt {
    my $p   = shift;
    my %sdt = @_;

    $sdt{ original_network_id } = $p->GetWord();
    $sdt{ reserved_3          } = $p->GetByte();

    # Service loop
    my @service_list = ();
    while (0 < $p->GetRemainBytesOfSection()) {
        my %service = (
            service_id                 => $p->GetWord(),
            reserved                   => $p->Get( 6),
            EIT_schedule_flag          => $p->Get( 1),
            EIT_present_following_flag => $p->Get( 1),
            running_status             => $p->Get( 3),
            free_CA_mode               => $p->Get( 1),
            descriptor_length          => $p->Get(12)
        );
        $service{ descriptor } =
            get_descriptor($p, $service{ descriptor_length });
        push(@service_list, \%service);

        if (0 < $dump_summary) {
            printf "#%d tsid 0x%04X onid 0x%04X svcid 0x%04X \n",
                $#service_list + 1,
                $sdt{ table_extension_id },
                $sdt{ original_network_id },
                $service{ service_id };
        }
    }
    $sdt{ service_list } = \@service_list;

    return %sdt;
}

#=========================================================================
# EIT
#=========================================================================
sub get_eit {
    my $p   = shift;
    my %eit = @_;

    $eit{ transport_stream_id }         = $p->GetWord();
    $eit{ original_network_id }         = $p->GetWord();
    $eit{ segment_last_section_number } = $p->GetByte();
    $eit{ last_table_id }               = $p->GetByte();

    # Event loop
    my @event_list = ();
    while (0 < $p->GetRemainBytesOfSection()) {
        my %event = (
            event_id          => $p->GetWord(),
            start_time_mjd    => $p->Get(16), # Modified Jullian Date
            start_time_utc    => $p->Get(24), # 6 digits 4-bit BCD
            duration          => $p->Get(24), # 6 digits 4-bit BCD
            running_status    => $p->Get( 3),
            free_CA_mode      => $p->Get( 1),
            descriptor_length => $p->Get(12)
        );
        $event{ descriptor } =
            get_descriptor($p, $event{ descriptor_length });
        push(@event_list, \%event);

        if (0 < $dump_summary) {
            printf "#%d tsid 0x%04X onid 0x%04X svcid 0x%04X eventid 0x%04X\n",
                $#event_list + 1,
                $eit{ transport_stream_id },
                $eit{ original_network_id },
                $eit{ table_extension_id },
                $event{ event_id };
        }
    }
    $eit { event_list } = \@event_list;

    return %eit;
}

#=========================================================================
# TOT/TDT
#=========================================================================
sub get_tot_tdt {
    my $p       = shift;
    my %tot_tdt = @_;

    $tot_tdt{ UTC_time_mjd } = $p->Get(16); # Modified Jullian Date
    $tot_tdt{ UTC_time_utc } = $p->Get(24); # 6 digits 4-bit BCD

    # TOT
    if (0x73 == $tot_tdt{ table_id }) {
        $p->Skip(4);
        $tot_tdt{ descriptor_length } = $p->Get(12);
        $tot_tdt{ descriptor        } = get_descriptor($p, $tot_tdt{ descriptor_length });
    }

    return %tot_tdt;
}

#=========================================================================
# CLT
#=========================================================================
sub get_clt {
    my $p   = shift;
    my %clt = @_;

    $clt{ current_day       } = $p->GetWord();
    $clt{ how_many_days_epg } = $p->Get(4);
    $clt{ languages         } = $p->Get(4);

    # Program loop
    my @program_list = ();
    my $index = 0;
    while (0 < $p->GetRemainBytesOfSection()) {
        my %program = (
            program_index       => $index,
            original_network_id => $p->GetWord(),
            transport_stream_id => $p->GetWord(),
            service_id          => $p->GetWord(),
            descriptor_count    => $p->GetWord(),
        );
        $program{ descriptor } =
            get_descriptor_by_num($p, $program{ descriptor_count });
        push(@program_list, \%program);
        ++$index;

        if (0 < $dump_summary) {
            printf "#%d day %d days %d lang %d tsid 0x%04X onid 0x%04X svcid 0x%04X\n",
                $#program_list + 1,
                $clt{ current_day },
                $clt{ how_many_days_epg },
                $clt{ languages },
                $program{ transport_stream_id },
                $program{ original_network_id },
                $program{ service_id },
        }
    }
    $clt{ program_list } = \@program_list;

    return %clt;
}

#=========================================================================
# PDT
#=========================================================================
sub get_pdt {
    my $p   = shift;
    my %pdt = @_;

    if (0 == $pdt{ section_number }) {
        $pdt{ compression_flag } = $p->Get(1);
        $p->Skip(7);
    } else {
        $pdt{ compression_flag } = undef;
    }
    my @pis = $p->GetBytes($p->GetRemainBytesOfSection());
    $pdt{ ref_pis } = \@pis;

    return %pdt;
}

##########################################################################
#
# DUMP (Section)
#
##########################################################################

#=========================================================================
# dump TS header
#=========================================================================
sub dump_ts_header {
    my %ts_header = @_;

    printf "===== TS HEADER BEGIN =====\n";
    printf "- synchronization_byte         0x%02X\n", $ts_header{ synchronization_byte };
    printf "- transport_error_indicator    %d    \n", $ts_header{ transport_error_indicator };
    printf "- payload_unit_start_indicator %d    \n", $ts_header{ payload_unit_start_indicator };
    printf "- transport_priority           %d    \n", $ts_header{ transport_priority };
    printf "- pid                          0x%04X\n", $ts_header{ pid };
    printf "- transport_scrambling_control %d    \n", $ts_header{ transport_scrambling_control };
    printf "- adaptation_field_control     %d    \n", $ts_header{ adaptation_field_control };
    printf "- continuity_index             %d    \n", $ts_header{ continuity_index };
    printf "===== TS HEADER END =======\n";
}

#=========================================================================
# dump Private Section
#=========================================================================
sub dump_private_section {
    my %sec = @_;
    printf "===== PRIVATE SECTION BEGIN =====\n";
    printf "  table_id                 0x%02X \n", $sec{ table_id };
    printf "  section_syntax_indicator %d \n",     $sec{ section_syntax_indicator };
    printf "  section_length           %d \n",     $sec{ section_length };
    printf "  table_extension_id       0x%04X \n", $sec{ table_extension_id };
    printf "  version_number           %d \n",     $sec{ version_number };
    printf "  current_next_indicator   %d \n",     $sec{ current_next_indicator };
    printf "  section_number           %d \n",     $sec{ section_number };
    printf "  last_section_number      %d \n",     $sec{ last_section_number };
    printf "  (payload_length          %d)\n",     $sec{ payload_length };
    printf "===== PRIVATE SECTION END =======\n";
}

#=========================================================================
# dump table found
#=========================================================================
sub dump_table_found {
    my $name      = shift;
    my $pid       = shift;
    my $index     = shift;
    my $ref_sec   = shift;

    printf "*** %s FOUND (%d) PID:0x%04X tbl:0x%02X ext:0x%04X v:%d section:%d/%d ***\n",
           $name,
           $index,
           $pid,
           $ref_sec->{ table_id },
           $ref_sec->{ table_extension_id },
           $ref_sec->{ version_number },
           $ref_sec->{ section_number },
           $ref_sec->{ last_section_number };
}

#=========================================================================
# dump PAT
#=========================================================================
sub dump_pat {
    my %pat = @_;

    my $ref_program_list = $pat{ program_list };
    my @program_list = @$ref_program_list;

    printf "===== PAT BEGIN =====\n";
    my $ref_program;
    foreach $ref_program (@program_list) {
        printf "  program_number %d PID 0x%04X\n",
            $ref_program->{ program_number },
            $ref_program->{ PID };
    }
    printf "===== PAT END =======\n";
}

#=========================================================================
# dump PMT
#=========================================================================
sub dump_pmt {
    my %pmt = @_;

    printf "===== PMT BEGIN =====\n";
    printf "  PCR_PID %d\n", $pmt{ PCR_PID };
    dump_descriptors($pmt{ descriptor_program });

    # ES loop
    printf "  ----- ES LOOP BEGIN -----\n";
    my $ref_es_list = $pmt{ es_list };
    foreach my $ref_es (@$ref_es_list) {
        printf "  pgm 0x%04X(%d) type 0x%02X ES_PID 0x%04X \n",
            $pmt{ table_extension_id },
            $pmt{ table_extension_id },
            $ref_es->{ stream_type },
            $ref_es->{ elementary_PID };
        dump_descriptors($ref_es->{ descriptor });
    }

    printf "  ----- ES LOOP END -------\n";
    printf "===== PMT END =======\n";
}

#=========================================================================
# dump NIT
#=========================================================================
sub dump_nit {
    my %nit = @_;

    printf "===== NIT BEGIN =====\n";
    printf "  table_id 0x%02X network_id 0x%04X\n",
        $nit{ table_id }, $nit{ table_extension_id };
    dump_descriptors($nit{ descriptor });

    # Network loop
    printf "  ----- TS LOOP BEGIN -----\n";
    my $ref_network_list = $nit{ network_list };
    foreach my $ref_network (@$ref_network_list) {
        printf "  tsid 0x%04x onid 0x%04x \n",
            $ref_network->{ transport_stream_id },
            $ref_network->{ original_network_id };
        dump_descriptors($ref_network->{ descriptor });
    }

    printf "  ----- TS LOOP END -------\n";
    printf "===== NIT END =======\n";
}

#=========================================================================
# dump BAT
#=========================================================================
sub dump_bat {
    my %bat = @_;

    printf "===== BAT BEGIN =====\n";
    printf "  table_id 0x%02X bouquet_id 0x%04X\n",
        $bat{ table_id }, $bat{ table_extension_id };
    dump_descriptors($bat{ descriptor });

    # TS loop
    printf "  ----- TS LOOP BEGIN -----\n";
    my $ref_ts_list = $bat{ ts_list };
    foreach my $ref_ts (@$ref_ts_list) {
        printf "  tsid 0x%04x onid 0x%04x \n",
            $ref_ts->{ transport_stream_id },
            $ref_ts->{ original_network_id };
        dump_descriptors($ref_ts->{ descriptor });
    }

    printf "  ----- TS LOOP END -------\n";
    printf "===== BAT END =======\n";
}

#=========================================================================
# dump SDT
#=========================================================================
sub dump_sdt {
    my %sdt = @_;

    printf "===== SDT BEGIN =====\n";

    # Service loop
    printf "  ----- SERVICE LOOP BEGIN -----\n";
    my $ref_service_list = $sdt{ service_list };
    foreach my $ref_service (@$ref_service_list) {
        printf "  tsid 0x%04X onid 0x%04X svcid 0x%04X EITs/p %d/%d running %d free_CA %d\n",
            $sdt{ table_extension_id },
            $sdt{ original_network_id },
            $ref_service->{ service_id },
            $ref_service->{ EIT_schedule_flag },
            $ref_service->{ EIT_present_following_flag },
            $ref_service->{ running_status },
            $ref_service->{ free_CA_mode };
        # printf "  desc_len %d\n", $ref_service->{ descriptor_length };
        dump_descriptors($ref_service->{ descriptor });
    }
    printf "  ----- SERVICE LOOP END -------\n";
    printf "===== SDT END =======\n";
}

#=========================================================================
# dump EIT
#=========================================================================
sub dump_eit {
    my %eit = @_;

    printf "===== EIT BEGIN =====\n";
    printf "  table_id 0x%02X tsid 0x%04X onid 0x%04X svcid 0x%04X\n",
        $eit{ table_id            },
        $eit{ transport_stream_id },
        $eit{ original_network_id },
        $eit{ table_extension_id  };

    # Event loop
    printf "  ----- EVENT LOOP BEGIN -----\n";
    my $ref_event_list = $eit{ event_list };
    foreach my $ref_event (@$ref_event_list) {
        printf "  event_id 0x%04X running %d free_CA %d\n",
            $ref_event->{ event_id       },
            $ref_event->{ running_status },
            $ref_event->{ free_CA_mode   };
        printf "  start_time ";
        dump_utc_time($ref_event->{ start_time_mjd }, $ref_event->{ start_time_utc });
        printf "  duration   ";
        dump_hhmmss($ref_event->{ duration }, 6); # 6digits BCD
        # printf "  desc_len %d\n", $ref_event->{ descriptor_length };
        dump_descriptors($ref_event->{ descriptor });
    }
    printf "  ----- EVENT LOOP END -------\n";
    printf "===== EIT END =======\n";
}

#=========================================================================
# dump TOT/TDT
#=========================================================================
sub dump_tot_tdt {
    my %tot_tdt = @_;

    print "===== TOT/TDT BEGIN =====\n";
    print "  UTC_time ";
    dump_utc_time($tot_tdt{ UTC_time_mjd }, $tot_tdt{ UTC_time_utc });
    dump_descriptors($tot_tdt{ descriptor });
    print "===== TOT/TDT END =====\n";
}

#=========================================================================
# dump CLT
#=========================================================================
sub dump_clt {
    my %clt = @_;

    printf "===== CLT BEGIN =====\n";
    printf "  table_id 0x%02X day %d days %d lang %d\n",
        $clt{ table_id          },
        $clt{ current_day       },
        $clt{ how_many_days_epg },
        $clt{ languages         };

    # Program loop
    printf "  ----- PROGRAM LOOP BEGIN -----\n";
    my $ref_program_list = $clt{ program_list };
    foreach my $ref_program (@$ref_program_list) {
        printf "  prog %d tsid 0x%04X onid 0x%04X svcid 0x%04X\n",
            $ref_program->{ program_index },
            $ref_program->{ transport_stream_id },
            $ref_program->{ original_network_id },
            $ref_program->{ service_id };
        # printf "  desc_count %d\n", $ref_program->{ descriptor_count };
        dump_descriptors($ref_program->{ descriptor });
    }
    printf "  ----- PROGRAM LOOP END -------\n";
    printf "===== CLT END =======\n";
}

#=========================================================================
# dump PDT
#=========================================================================
sub dump_pdt {
    my %pdt = @_;

    my $ext  = $pdt{ table_extension_id };
    my $prog = ($ext & 0xff80) >> 7;
    my $day  = ($ext & 0x007f) >> 3;
    my $lang = ($ext & 0x0007);

    printf "===== PDT BEGIN =====\n";
    printf "  table_id 0x%02X prog %d day %d lang %d ",
        $pdt{ table_id },
        $prog,
        $day,
        $lang;
    if (defined($pdt{ compression_flag })) {
        printf "compression %d\n", $pdt{ compression_flag };
    } else {
        print  "compression -\n";
    }

    # find PIS entry
    my $pis = find_pis($prog, $day, $lang, $pdt{ version_number });
    unless (defined($pis)) {
#       printf "*** NEW PIS %d %d %d %d %d ****\n",
#              $prog, $day, $lang,
#              $pdt{ version_number },
#              $pdt{ last_section_number };
        $pis = new PolsatPIS($prog, $day, $lang,
                             $pdt{ version_number },
                             $pdt{ last_section_number });
        push(@polsat_pis_list, $pis);
    }
    $pis->SetPacket($pdt{ section_number }, $pdt{ ref_pis });
    if ($pis->IsComplete()) {
        if (2 <= $dump_polsat_epg) {
            my $filename = $pis->WriteBinaryFile();
            print "  pis data is written to $filename.\n";
        }
        elsif (1 <= $dump_polsat_epg) {
            print "  ----- PIS EVENT LOOP BEGIN -----\n";
            $pis->ParseAndDump();
            print "  ----- PIS EVENT LOOP END -----\n";
        }
    } else {
        print "  section has not been completed yet.\n";
    }
    printf "===== PDT END =======\n";
}

sub find_pis {
    my $prog    = shift;
    my $day     = shift;
    my $lang    = shift;
    my $version = shift;

    # serch PIS object.
    foreach my $pis (@polsat_pis_list) {
        if ($pis->IsSame($prog, $day, $lang, $version)) {
            return $pis;
        }
    }

    # NOT FOUND.
    return undef;
}

##########################################################################
#
# DUMP (descriptor)
#
##########################################################################

#=========================================================================
# descriptor dispatcher
#=========================================================================
sub dump_descriptors {
    my $ref_desc_list = shift;

    unless (defined($ref_desc_list)) { return; }

    # private data specifier
    my $pds = 0;

    my @desc_list = @$ref_desc_list; # de-reference

    print "  {\n" if (0 <= $#desc_list);
    foreach my $ref_desc (@desc_list) {
        my $tag = $ref_desc->{ descriptor_tag };
        my $len = $ref_desc->{ descriptor_length };
        printf "    tag:0x%02X len:%d\n", $tag, $len;

        my $desc = TSPacket->new;
        $desc->SetBuffer($ref_desc->{ desc_buf });
        $desc->SetDescriptorLength($len);

        if    (0xFF == $tag) { printf "      forbidden \n"; }

        my $unknown = 0;

        # MPEG
        if (0x00 == ($tag & 0xF0)) {
            if    (0x02 == $tag) { dump_descriptor_0x02($desc); }
            elsif (0x03 == $tag) { dump_descriptor_0x03($desc); }
            elsif (0x09 == $tag) { dump_descriptor_0x09($desc); }
            elsif (0x0a == $tag) { dump_descriptor_0x0a($desc); }
            elsif (0x0b == $tag) { dump_descriptor_0x0b($desc); }
            elsif (0x0e == $tag) { dump_descriptor_0x0e($desc); }
            elsif (0x0f == $tag) { dump_descriptor_0x0f($desc); }
            else { $unknown = 1; }
        }
        elsif (0x10 == ($tag & 0xF0)) {
            if    (0x10 == $tag) { dump_descriptor_0x10($desc); }
            elsif (0x13 == $tag) { dump_descriptor_0x13($desc); }
            else { $unknown = 1; }
        }

        # DVB-SI
        elsif (0x40 == ($tag & 0xF0)) {
            if    (0x40 == $tag) { dump_descriptor_0x40($desc, $len); }
            elsif (0x41 == $tag) { dump_descriptor_0x41($desc); }
            elsif (0x42 == $tag) { dump_descriptor_0x42($desc); }
            elsif (0x43 == $tag) { dump_descriptor_0x43($desc); }
            elsif (0x44 == $tag) { dump_descriptor_0x44($desc); }
            elsif (0x45 == $tag) { dump_descriptor_0x45($desc); }
            elsif (0x46 == $tag) { dump_descriptor_0x56($desc); } # same as 0x56
            elsif (0x47 == $tag) { dump_descriptor_0x47($desc, $len); }
            elsif (0x48 == $tag) { dump_descriptor_0x48($desc); }
            elsif (0x49 == $tag) { dump_descriptor_0x49($desc); }
            elsif (0x4a == $tag) { dump_descriptor_0x4a($desc); }
            elsif (0x4b == $tag) { dump_descriptor_0x4b($desc); }
            elsif (0x4c == $tag) { dump_descriptor_0x4c($desc); }
            elsif (0x4d == $tag) { dump_descriptor_0x4d($desc); } # SED
            elsif (0x4e == $tag) { dump_descriptor_0x4e($desc); } # EED
            elsif (0x4f == $tag) { dump_descriptor_0x4f($desc); }
            else { $unknown = 1; }
        }
        elsif (0x50 == ($tag & 0xF0)) {
            if    (0x50 == $tag) { dump_descriptor_0x50($desc); }
            elsif (0x51 == $tag) { dump_descriptor_0x51($desc); }
            elsif (0x52 == $tag) { dump_descriptor_0x52($desc); }
            elsif (0x53 == $tag) { dump_descriptor_0x53($desc); }
            elsif (0x54 == $tag) { dump_descriptor_0x54($desc); }
            elsif (0x55 == $tag) { dump_descriptor_0x55($desc); }
            elsif (0x56 == $tag) { dump_descriptor_0x56($desc); }
            elsif (0x57 == $tag) { dump_descriptor_0x57($desc); }
            elsif (0x58 == $tag) { dump_descriptor_0x58($desc); }
            elsif (0x59 == $tag) { dump_descriptor_0x59($desc); }
            elsif (0x5a == $tag) { dump_descriptor_0x5a($desc); }
            elsif (0x5b == $tag) { dump_descriptor_0x5b($desc); }
            elsif (0x5c == $tag) { dump_descriptor_0x5c($desc); }
            elsif (0x5d == $tag) { dump_descriptor_0x5d($desc); }
            elsif (0x5e == $tag) { dump_descriptor_0x5e($desc); }
            elsif (0x5f == $tag) { $pds = dump_descriptor_0x5f($desc); }
            else { $unknown = 1; }
        }
        elsif (0x60 == ($tag & 0xF0)) {
            if    (0x60 == $tag) { dump_descriptor_0x60($desc); }
            elsif (0x61 == $tag) { dump_descriptor_0x61($desc); }
            elsif (0x62 == $tag) { dump_descriptor_0x62($desc); }
            elsif (0x63 == $tag) { dump_descriptor_0x63($desc); }
            elsif (0x64 == $tag) { dump_descriptor_0x64($desc); }
            elsif (0x65 == $tag) { dump_descriptor_0x65($desc); }
            elsif (0x66 == $tag) { dump_descriptor_0x66($desc); }
            elsif (0x67 == $tag) { dump_descriptor_0x67($desc); }
            elsif (0x68 == $tag) { dump_descriptor_0x68($desc); }
            elsif (0x69 == $tag) { dump_descriptor_0x69($desc); }
            elsif (0x6a == $tag) { dump_descriptor_0x6a($desc); }
            elsif (0x6b == $tag) { dump_descriptor_0x6b($desc); }
            elsif (0x6c == $tag) { dump_descriptor_0x6c($desc); }
            elsif (0x6d == $tag) { dump_descriptor_0x6d($desc); }
            elsif (0x6e == $tag) { dump_descriptor_0x6e($desc); }
            elsif (0x6f == $tag) { dump_descriptor_0x6f($desc); }
            else { $unknown = 1; }
        }
        elsif (0x70 == ($tag & 0xF0)) {
            if    (0x70 == $tag) { dump_descriptor_0x70($desc); }
            elsif (0x72 == $tag) { dump_descriptor_0x72($desc); }
            elsif (0x76 == $tag) { dump_descriptor_0x76($desc); }
            elsif (0x79 == $tag) { dump_descriptor_0x79($desc); }
            elsif (0x7a == $tag) { dump_descriptor_0x7a($desc); }
            elsif (0x7b == $tag) { dump_descriptor_0x7b($desc); }
            elsif (0x7c == $tag) { dump_descriptor_0x7c($desc); }
            elsif (0x7e == $tag) { dump_descriptor_0x7e($desc); }
            elsif (0x7f == $tag) {
                my $tag_ext = $desc->Get(8);
                if    (0x00 == $tag_ext) { dump_desc_ext_0x00($desc); }
                elsif (0x02 == $tag_ext) { dump_desc_ext_0x02($desc); }
                elsif (0x03 == $tag_ext) { dump_desc_ext_0x03($desc); }
                elsif (0x04 == $tag_ext) { dump_desc_ext_0x04($desc); }
                elsif (0x08 == $tag_ext) { dump_desc_ext_0x08($desc); }
                elsif (0x0b == $tag_ext) { dump_desc_ext_0x0b($desc); }
                elsif (0x0d == $tag_ext) { dump_desc_ext_0x0d($desc); }
                else { $unknown = 1; }
            }
            else { $unknown = 1; }
        }

        # Generic 1-5-10 format LCN
        # - 0x83 with PDS 0x00000028 = EICTA LCN
        # - 0x83 with PDS 0x00000037 = NZDTG LCN
        # - 0xB0 with PDS 0x00000020
        #                         21
        #                         22
        #                         23 = Numericable LCN
        # - 0x83 with PDS 0x00564f4f = Voo LCN
        # - 0x88 with PDS 0x00000028 = Ziggo LCN
        # - 0x89 with PDS 0x0000233A = UK DTG LCN
        elsif ((0x00000028 == $pds && 0x83 == $tag) ||
               (0x00000037 == $pds && 0x83 == $tag) ||
               (0x00000020 == $pds && 0xb0 == $tag) ||
               (0x00000021 == $pds && 0xb0 == $tag) ||
               (0x00000022 == $pds && 0xb0 == $tag) ||
               (0x00000023 == $pds && 0xb0 == $tag) ||
               (0x00564f4f == $pds && 0x83 == $tag) ||
               (0x00000028 == $pds && 0x88 == $tag) ||
               (0x0000233a == $pds && 0x89 == $tag)) {
            dump_descriptor_generic_1_5_10_lcn($desc);
        }

        # 1-1-14 format LCN
        # - 0x83 with PDS 0x00000029 = Nordig V1 LCN
        # - 0x83 with PDS 0x00000083 = Denmark YouSee LCN
        # - 0x83 with PDS 0xfcfcfcfc = Denmark YouSee LCN
        elsif ((0x00000029 == $pds && 0x83 == $tag) ||
               (0x00000083 == $pds && 0x83 == $tag) ||
               (0xfcfcfcfc == $pds && 0x83 == $tag)) {
            dump_descriptor_nordig_v1_lcn($desc);
        }

        # Generic 6-10 format LCN
        # - 0x83 with PDS 0x0000233A = UK DTG LCN
        elsif (0x0000233A == $pds && 0x83 == $tag) {
            dump_descriptor_generic_6_10_lcn($desc);
        }

        # Generic 16 format LCN
        # - 0xE2 = Akado, D-Smart, Norway GET, China(GZ/SZ)
        # - 0x82 with PDS 0x00000031 = YouSee LCN
        elsif ((0xe2 == $tag) ||
               (0x00000031 == $pds && 0x82 == $tag)) {
            dump_descriptor_generic_16_lcn($desc);
        }

        # LCN
        # - 0x87 with PDS 0x00000029 = Nordig V2 LCN
        elsif (0x00000029 == $pds && 0x87 == $tag) {
            dump_descriptor_nordig_v2_lcn($desc);
        }

        # LCN
        # - 0x87 with PDS 0x000021CA = MYS V2 LCN
        #        with PDS 0x00000019 = SGP V2 LCN
        elsif ((0x000021ca == $pds && 0x87 == $tag) ||
               (0x00000019 == $pds && 0x87 == $tag)) {
            dump_descriptor_MYS_SGP_v2_lcn($desc);
        }

        # LCN
        # - 0x87 with No PDS = THAI LCN
        elsif (0x87 == $tag) {
            dump_descriptor_MYS_SGP_v2_lcn($desc);
        }

        # LCN
        # - 0x88 with PDS 0x00000028 = EICTA HD SIMULCAST LCN
        # - 0x88 with PDS 0x0000233A = UK DTG HD SIMULCAST LCN
        # - 0x88 with no PDS         = (defact) HD SIMULCAST LCN
        elsif ((0x00000028 == $pds && 0x88 == $tag) ||
               (0x0000233a == $pds && 0x88 == $tag) ||
               (         0 == $pds && 0x88 == $tag)) {
            dump_descriptor_hd_simulcast_lcn($desc);
        }

        # OTHER
        # - 0x81 with PDS 0x00000039 = Channel descriptor 3 (Polsat)
        elsif (0x00000039 == $pds && 0x81 == $tag) {
            dump_descriptor_channel_3($desc);
        }

        # OTHER
        # - 0x86 with PDS 0x0000233a = Service Attribute Descriptor
        elsif (0x0000233a == $pds && 0x86 == $tag) {
            dump_descriptor_service_attribute($desc);
        }

        # OTHER
        # - 0xE4 with PDS 0x00006001 = NDS SERVICE ORDER LIST
        elsif (0x00006001 == $pds && 0xe4 == $tag) {
            dump_descriptor_nds_service_order_list($desc);
        }

        # OTHER
        # - 0xCE with PDS 0x00000040 = ci_protection_descriptor
        elsif (0x00000040 == $pds && 0xce == $tag) {
            dump_descriptor_ci_protection($desc);
        }

        # Not processed.
        else { $unknown = 1; }

        if (1 == $unknown) {
            printf "      unknown tag 0x%02X\n", $ref_desc->{ descriptor_tag };
            dump_descriptor_data_in_hex("      ", $desc);
        }
    }
    print "  }\n" if (0 <= $#desc_list);
}

#=========================================================================
# 0x02 : video_stream_descriptor
#=========================================================================
sub dump_descriptor_0x02 {
    my $desc = shift;
    printf "      (video_stream_descriptor)\n";
    dump_descriptor_data_in_hex("      ", $desc);
}

#=========================================================================
# 0x03 : audio_stream_descriptor
#=========================================================================
sub dump_descriptor_0x03 {
    my $desc = shift;
    printf "      (audio_stream_descriptor)\n";
    dump_descriptor_data_in_hex("      ", $desc);
}

#=========================================================================
# 0x09 : CA_descriptor
#=========================================================================
sub dump_descriptor_0x09 {
    my $desc = shift;
    printf "      (CA_descriptor)\n";
    printf "      CA_system_ID      0x%04X\n", $desc->GetWord();
                                             $desc->Skip(3);
    printf "      CA_PID            0x%04X\n", $desc->Get(13);
    if (0 < $desc->GetRemainBytesOfDescriptor()) {
        dump_descriptor_data_in_hex("      private_data_byte ", $desc);
    }
}

#=========================================================================
# 0x0a : ISO_639_language_descriptor
#=========================================================================
sub dump_descriptor_0x0a {
    my $desc = shift;
    while (0 < $desc->GetRemainBytesOfDescriptor()) {
        print  "      ISO_639_language_code "; dump_ISO639($desc->GetBytes(3));
        printf "      audio_type            %d\n", $desc->Get(8);
    }
}

#=========================================================================
# 0x0b : system_clock_descriptor
#=========================================================================
sub dump_descriptor_0x0b {
    my $desc = shift;
    printf "      external_clock_reference_indicator %d\n", $desc->Get (1);
                                                          $desc->Skip(1);
    printf "      clock_accuracy_integer             %d\n", $desc->Get (6);
    printf "      clock_accuracy_exponent            %d\n", $desc->Get (3);
                                                          $desc->Skip(5);
}

#=========================================================================
# 0x0e : maximum_bitrate_descriptor
#=========================================================================
sub dump_descriptor_0x0e {
    my $desc = shift;
    printf "      (maximum_bitrate_descriptor)\n";
    dump_descriptor_data_in_hex("      ", $desc);
}

#=========================================================================
# 0x0f : private_data_indicator_descriptor
#=========================================================================
sub dump_descriptor_0x0f {
    my $desc = shift;
    printf "      private_data_indicator 0x%08X\n", $desc->Get(32);
}

#=========================================================================
# 0x10 : smoothing_buffer_descriptor
#=========================================================================
sub dump_descriptor_0x10 {
    my $desc = shift;
    printf "      (smoothing_buffer_descriptor)\n";
    dump_descriptor_data_in_hex("      ", $desc);
}

#=========================================================================
# 0x13 : carousel_identifier_descriptor
#=========================================================================
sub dump_descriptor_0x13 {
    my $desc = shift;
    printf "      (carousel_identifier_descriptor)\n";
    dump_descriptor_data_in_hex("      ", $desc);
}

#=========================================================================
# 0x40 : network_name_descriptor
#=========================================================================
sub dump_descriptor_0x40 {
    my $desc = shift;
    my $len  = shift;
    printf "      network_name ";
    dump_string($desc->GetBytes($len));
}

#=========================================================================
# 0x41 : service_list_descriptor
#=========================================================================
sub dump_descriptor_0x41 {
    my $desc = shift;
    printf "      (service_list_descriptor)\n";
    while (0 < $desc->GetRemainBytesOfDescriptor()) {
        printf "      service_id 0x%04X service_type 0x%02X\n",
            $desc->GetWord(),
            $desc->GetByte();
    }
}

#=========================================================================
# 0x42 : stuffing_descriptor
#=========================================================================
sub dump_descriptor_0x42 {
    my $desc = shift;
    printf "      (stuffing_descriptor)\n";
    dump_descriptor_data_in_hex("      ", $desc);
}

#=========================================================================
# 0x43 : satellite_delivery_system_descriptor
#=========================================================================
sub dump_descriptor_0x43 {
    my $desc = shift;
    #$desc->Dump();
    printf "      (satellite_delivery_system_descriptor)\n";
    printf "      frequency         "; dump_4bitBCD($desc->GetDWord()); # 4bit BCD
    printf "      orbital_position  "; dump_4bitBCD($desc->GetWord());  # 4bit BCD
    printf "      west_east_flag    %d\n", $desc->Get(1);
    printf "      polarization      %d\n", $desc->Get(2);
    printf "      roll_off_or_00    %d\n", $desc->Get(2);
    printf "      modulation_system %d\n", $desc->Get(1);
    printf "      modulation_type   %d\n", $desc->Get(2);
    printf "      symbol_rate       "; dump_4bitBCD($desc->Get(28));
    printf "      FEC_inner         %d\n", $desc->Get(4);
}

#=========================================================================
# 0x44 : cable_delivery_system_descriptor
#=========================================================================
sub dump_descriptor_0x44 {
    my $desc = shift;
    #$desc->Dump();
    printf "      (cable_delivery_system_descriptor)\n";
    printf "      frequency   "; dump_4bitBCD($desc->GetDWord()); # 4bit BCD
    $desc->Skip(12);
    printf "      FEC_outer   %d     \n", $desc->Get(4);
    printf "      modullation 0x%02X \n", $desc->GetByte();
    printf "      symbol_rate "; dump_4bitBCD($desc->Get(28)); # 4bit BCD
    printf "      FEC_inner   %d     \n", $desc->Get(4);
}

#=========================================================================
# 0x45 : VBI_data_descriptor
#=========================================================================
sub dump_descriptor_0x45 {
    my $desc = shift;
    printf "      (VBI_data_descriptor)\n";
    while (0 < $desc->GetRemainBytesOfDescriptor()) {
        my $id  = $desc->GetByte();
        my $len = $desc->GetByte();
        printf "      data_service_id                %d\n", $id;
        printf "      data_service_descriptor_length %d\n", $len;
        if (0x01 == $id ||
            0x02 == $id ||
            0x04 == $id ||
            0x05 == $id ||
            0x06 == $id ||
            0x07 == $id) {
            for (my $i = 0; $i < $len; ++$i) {
                printf "      reserved     %d\n", $desc->Get(2);
                printf "      field_parity %d\n", $desc->Get(1);
                printf "      line_offset  %d\n", $desc->Get(5);
            }
        } else {
            printf "      reserved ";
            dump_hex($desc->GetBytes($len));
        }
    }
}

#=========================================================================
# 0x47 : bouquet_name_descriptor
#=========================================================================
sub dump_descriptor_0x47 {
    my $desc = shift;
    my $len  = shift;
    printf "      bouquet_name ";
    dump_string($desc->GetBytes($len));
}

#=========================================================================
# 0x48 : service_descriptor
#=========================================================================
sub dump_descriptor_0x48 {
    my $desc = shift;
    printf "      (service_descriptor)\n";
    printf "      service_type 0x%02X \n", $desc->GetByte();
    my $sp_len = $desc->GetByte();
    printf "      service_provider_name(%d) ", $sp_len;
    dump_string($desc->GetBytes($sp_len));
    my $sv_len = $desc->GetByte();
    printf "      service_name(%d) ", $sv_len;
    dump_string($desc->GetBytes($sv_len));
}

#=========================================================================
# 0x49 : country_availability_descriptor
#=========================================================================
sub dump_descriptor_0x49 {
    my $desc = shift;
    printf "      (country_availability_descriptor)\n";
    printf "      country_availability_flag %d\n", $desc->Get( 1);
                                                   $desc->Skip(7);
    while (0 < $desc->GetRemainBytesOfDescriptor()) {
        printf "      country_code "; dump_ISO639($desc->GetBytes(3));
    }
}

#=========================================================================
# 0x4a : linkage_descriptor
#=========================================================================
sub dump_descriptor_0x4a {
    my $desc = shift;
    printf "      (linkage_descriptor)\n";
    printf "      transport_stream_id 0x%04X\n", $desc->GetWord();
    printf "      original_network_id 0x%04X\n", $desc->GetWord();
    printf "      service_id          0x%04X\n", $desc->GetWord();
    my $linkage_type = $desc->GetByte();
    print  "      linkage_type        "; dump_linkage_type($linkage_type);
    printf "(0x%02X)\n", $linkage_type;
    # likage info
    if (0x08 == $linkage_type) {
        # under construction
        printf "      (mobile_hand-over_info)\n";
        my $type = $desc->Get(4);
        $desc->Skip(3);
        printf "      origin_type %d\n", $desc->Get(1);
        if (0x01 == $type ||
            0x02 == $type ||
            0x03 == $type) {
            printf "      network_id 0x%04X\n", $desc->GetWord();
        } elsif (0x00 == $type) {
            printf "      initial_service_id 0x%04X\n", $desc->GetWord();
        }
    }
    elsif (0x0d == $linkage_type) {
        printf "      (event_linkage_info)\n";
        printf "      taget_event_id  0x%04X\n", $desc->GetWord();
        printf "      target_listed   %d\n",     $desc->Get(1);
        printf "      event_simulcast %d\n",     $desc->Get(1);
                                                 $desc->Skip(6);
    }
    elsif (0x0e == $linkage_type) {
        printf "      (extended_event_linkage_info)\n";
        my $loop = $desc->GetByte();
        printf "      loop_length %d\n", $loop;
        for (my $i = 0; $i < $loop; ++$i) {
            printf "      taget_event_id           0x%04X\n", $desc->GetWord();
            printf "      target_listed            %d\n", $desc->Get(1);
            printf "      event_simulcast          %d\n", $desc->Get(1);
            printf "      link_type                %d\n", $desc->Get(2);
            my $target_id_type = $desc->Get(2);
            printf "      target_id_type           %d\n", $target_id_type;
            my $onid_flag = $desc->Get(1);
            printf "      original_network_id_flag %d\n", $onid_flag;
            my $svcid_flag = $desc->Get(1);
            printf "      service_id_flag          %d\n", $svcid_flag;
            if (3 == $target_id_type) {
                printf "      user_defined_id 0x%04X\n", $desc->GetWord();
            } else {
                if (1 == $target_id_type) {
                    printf "      target_transport_stream_id 0x%04X\n", $desc->GetWord();
                }
                if (0 != $onid_flag) {
                    printf "      target_original_network_id 0x%04X\n", $desc->GetWord();
                }
                if (0 != $svcid_flag) {
                    printf "      target_service_id 0x%04X\n", $desc->GetWord();
                }
            }
        }
    }
    elsif (0x80 == $linkage_type) {
        printf "      (polsat_epg_info)\n";
        my $count = $desc->GetByte();
        printf "      transponder_count %d\n", $count;
        for (my $i = 0; $i < $count; ++$i) {
            printf "      epg_original_network_id 0x%04X\n", $desc->GetWord();
            printf "      epg_transport_stream_id 0x%04X\n", $desc->GetWord();
            printf "      reserved                %d\n",     $desc->Get(3);
            if (0 < $dump_polsat_epg) {
                $polsat_epg_pid = $desc->Get(13); # global value.
                printf "      pid_value               0x%04X\n", $polsat_epg_pid;
            } else {
                $polsat_epg_pid = undef;
                printf "      pid_value               0x%04X\n", $desc->Get(13);
            }
        }

    }
    dump_descriptor_data_in_hex("      private_data_byte ", $desc);
}

#=========================================================================
# 0x4b : NVOD_reference_descriptor
#=========================================================================
sub dump_descriptor_0x4b {
    my $desc = shift;
    printf "      (NVOD_refernece_descriptor)\n";
    while (0 < $desc->GetRemainBytesOfDescriptor()) {
        printf "      transport_stream_id 0x%04X\n", $desc->GetWord();
        printf "      original_network_id 0x%04X\n", $desc->GetWord();
        printf "      service_id          0x%04X\n", $desc->GetWord();
    }
}

#=========================================================================
# 0x4c : time_shifted_service_descriptor
#=========================================================================
sub dump_descriptor_0x4c {
    my $desc = shift;
    printf "      (time_shifted_service_descriptor)\n";
    printf "      refernece_service_id 0x%04\n", $desc->GetWord();
}

#=========================================================================
# 0x4d : short event descriptor
#=========================================================================
sub dump_descriptor_0x4d {
    my $desc = shift;
    printf "      (short_event_descriptor)\n";
    print  "      ISO_639_language_code "; dump_ISO639($desc->GetBytes(3));
    my $event_name_len = $desc->GetByte();
    printf  "      event_name_char       (%d) ", $event_name_len;
    dump_string($desc->GetBytes($event_name_len));
    my $text_len = $desc->GetByte();
    printf  "      text_char             (%d) ", $text_len;
    dump_string($desc->GetBytes($text_len));
}

#=========================================================================
# 0x4e : extended event descriptor
#=========================================================================
sub dump_descriptor_0x4e {
    my $desc = shift;
    printf "      (extended_event_descriptor)\n";
    printf "      descriptor_number      %d\n", $desc->Get(4);
    printf "      last_descriptor_number %d\n", $desc->Get(4);
    print  "      ISO_639_language_code  "; dump_ISO639($desc->GetBytes(3));
    my $length_of_items = $desc->GetByte();
    printf "      length_of_items        %d\n", $length_of_items;
    for (my $i = 0 ; $i < $length_of_items; ++$i) {
        my $item_desc_length = $desc->GetByte();
        printf "        item_description(%d) ", $item_desc_length;
        dump_string($desc->GetBytes($item_desc_length));
        my $item_length = $desc->GetByte();
        printf "        item(%d) ", $item_length;
        dump_string($desc->GetBytes($item_length));
    }
    my $text_length = $desc->GetByte();
    printf "      text_char(%d) ", $text_length;
    dump_string($desc->GetBytes($text_length));
}

#=========================================================================
# 0x4f : time_shifted_event_descriptor
#=========================================================================
sub dump_descriptor_0x4f {
    my $desc = shift;
    printf "      (time_shifted_event_descriptor)\n";
    printf "      reference_service_id 0x%04X\n", $desc->GetWord();
    printf "      reference_event_id   0x%04X\n", $desc->GetWord();
}

#=========================================================================
# 0x50 : component_descriptor
#=========================================================================
sub dump_descriptor_0x50 {
    my $desc = shift;
    printf "      (component_descriptor)\n";
    $desc->Skip(4);
    printf "      stream_content        %d\n",     $desc->Get(4);
    printf "      component_type        0x%02X\n", $desc->GetByte();
    printf "      conponent_tag         0x%02X\n", $desc->GetByte();
    print  "      ISO_639_language_code "; dump_ISO639($desc->GetBytes(3));
    my $length = $desc->GetRemainBytesOfDescriptor();
    printf "      text_char(%d)          ", $length;
    dump_string($desc->GetBytes($length));
}

#=========================================================================
# 0x51 : mosaic_descriptor
#=========================================================================
sub dump_descriptor_0x51 {
    my $desc = shift;
    printf "      (mosaic_descriptor)\n";
    printf "      mosaic_entry_point %d\n",                    $desc->Get( 1);
    printf "      number_of_horizontal_elementary_cells %d\n", $desc->Get( 3);
                                                               $desc->Skip(1);
    printf "      number_of_vertical_elementary_cells   %d\n", $desc->Get( 3);
    while (0 < $desc->GetRemainBytesOfDescriptor()) {
        printf "      logical_cell_id                %d\n", $desc->Get( 6);
                                                            $desc->Skip(7);
        printf "      logical_cell_presentation_info %d\n", $desc->Get( 3);
                                               my $length = $desc->Get( 8);
        printf "      elementary_cell_field_length   %d\n", $length;
        for (my $i = 0; $i < $length; ++$length) {
                                                    $desc->Skip(2);
            printf "      elementary_cell_id %d\n", $desc->Get( 6);
        }
        my $info = $desc->Get(8);
        if (0x01 == $info) {
            printf "      bouquet_id 0x%04X\n", $desc->GetWord();
        }
        elsif (0x02 == $info) {
            printf "      original_network_id 0x%04X\n", $desc->GetWord();
            printf "      transport_stream_id 0x%04X\n", $desc->GetWord();
            printf "      service_id          0x%04X\n", $desc->GetWord();
        }
        elsif (0x03 == $info) {
            printf "      original_network_id 0x%04X\n", $desc->GetWord();
            printf "      transport_stream_id 0x%04X\n", $desc->GetWord();
            printf "      service_id          0x%04X\n", $desc->GetWord();
        }
        elsif (0x04 == $info) {
            printf "      original_network_id 0x%04X\n", $desc->GetWord();
            printf "      transport_stream_id 0x%04X\n", $desc->GetWord();
            printf "      service_id          0x%04X\n", $desc->GetWord();
            printf "      event_id            0x%04X\n", $desc->GetWord();
        }
    }
}

#=========================================================================
# 0x52 : stream_identifier_descriptor
#=========================================================================
sub dump_descriptor_0x52 {
    my $desc = shift;
    printf "      component_tag %d\n", $desc->GetByte();
}

#=========================================================================
# 0x53 : CA_identifier_descriptor
#=========================================================================
sub dump_descriptor_0x53 {
    my $desc = shift;
    printf "      (CA_identifier_descriptor)\n";
    while (0 < $desc->GetRemainBytesOfDescriptor()) {
        printf "      CA_system_id 0x%04X\n", $desc->GetWord();
    }
}

#=========================================================================
# 0x54 : content_descriptor
#=========================================================================
sub dump_descriptor_0x54 {
    my $desc = shift;
    while (0 < $desc->GetRemainBytesOfDescriptor()) {
        printf "      content_nibble_level_1 %d     \n", $desc->Get(4);
        printf "      content_nibble_level_2 %d     \n", $desc->Get(4);
        printf "      user_byte              0x%02X \n", $desc->GetByte();
    }
}

#=========================================================================
# 0x55 : parental_rating_descriptor
#=========================================================================
sub dump_descriptor_0x55 {
    my $desc = shift;
    printf "      (parental_rating_descriptor)\n";
    while (0 < $desc->GetRemainBytesOfDescriptor()) {
        printf "      country_code "; dump_ISO639($desc->GetBytes(3));
        printf "      rating       %d\n", $desc->GetByte();
    }
}

#=========================================================================
# 0x56 : teletext_descriptor
#=========================================================================
sub dump_descriptor_0x56 {
    my $desc = shift;
    printf "      (teletext_descriptor)\n";
    while (0 < $desc->GetRemainBytesOfDescriptor()) {
        print  "      ISO_639_language_code    "; dump_ISO639($desc->GetBytes(3));
        printf "      teletext_type            %d \n", $desc->Get(5);
        printf "      teletext_magazine_number %d \n", $desc->Get(3);
        printf "      teletext_page_number     %d \n", $desc->GetByte();
    }
}

#=========================================================================
# 0x57 : telephone_descriptor
#=========================================================================
sub dump_descriptor_0x57 {
    my $desc = shift;
    printf "      (telephone_descriptor)\n";
                                              $desc->Skip(2);
    printf "      foreign_availability %d\n", $desc->Get (1);
    printf "      connection_type      %d\n", $desc->Get (5);
                                              $desc->Skip(1);
    my $country_prefix_length =               $desc->Get (2);
    my $international_area_code_length =      $desc->Get (3);
    my $operator_code_length =                $desc->Get (2);
                                              $desc->Skip(1);
    my $national_area_code_length =           $desc->Get (3);
    my $core_number_length =                  $desc->Get (4);
    printf "      country_prefix ";
    dump_hex($desc->GetBytes($country_prefix_length));
    printf "      international_area_code ";
    dump_hex($desc->GetBytes($international_area_code_length));
    printf "      operator_code ";
    dump_hex($desc->GetBytes($operator_code_length));
    printf "      natonal_area_code ";
    dump_hex($desc->GetBytes($national_area_code_length));
    printf "      core_number ";
    dump_hex($desc->GetBytes($core_number_length));
}

#=========================================================================
# 0x58 : local_time_offset_descriptor
#=========================================================================
sub dump_descriptor_0x58 {
    my $desc = shift;
    printf "    (local_time_offset_descriptor)\n";
    while (0 < $desc->GetRemainBytesOfDescriptor()) {
        printf "      country_code               "; dump_ISO639($desc->GetBytes(3));
        printf "      country_region_id          %d\n", $desc->Get(6);
                                                      $desc->Skip(1);
        printf "      local_time_offset_polarity %d\n", $desc->Get(1);
        printf "      local_time_offset          "; dump_mmss($desc->GetWord());
        printf "      time_of_change             ";
        dump_utc_time($desc->GetWord(), $desc->Get(24));
        printf "      next_time_offset           "; dump_mmss($desc->GetWord());
    }
}

#=========================================================================
# 0x59 : subtitling_descriptor
#=========================================================================
sub dump_descriptor_0x59 {
    my $desc = shift;
    while (0 < $desc->GetRemainBytesOfDescriptor()) {
        print  "      ISO_639_language_code "; dump_ISO639($desc->GetBytes(3));
        printf "      subtitling_type       %d\n", $desc->GetByte();
        printf "      composition_page_id   %d\n", $desc->GetWord();
        printf "      ancillary_page_id     %d\n", $desc->GetWord();
    }
}

#=========================================================================
# 0x5a : terrestrial_delivery_system_descriptor
#=========================================================================
sub dump_descriptor_0x5a {
    my $desc = shift;
    printf "      center_frequency       %d\n", $desc->Get(32);
    printf "      band_width             "; dump_bandwidth($desc->Get(3));
    printf "      priority               %d\n", $desc->Get(1);
    printf "      Time_Slicing_indecator %d\n", $desc->Get(1);
    printf "      MPE-FEC_indicator      %d\n", $desc->Get(1);
    $desc->Skip(2);
    printf "      constellation          %d\n", $desc->Get(2);
    printf "      hierarchy_information  %d\n", $desc->Get(3);
    printf "      code_rate-HP_system    %d\n", $desc->Get(3);
    printf "      code_rate-LP_system    %d\n", $desc->Get(3);
    printf "      guard_interval         %d\n", $desc->Get(2);
    printf "      transmission_mode      %d\n", $desc->Get(2);
    printf "      other_frequency_flag   %d\n", $desc->Get(1);
    $desc->Skip(32);
}

#=========================================================================
# 0x5b : multilingual_network_name_descriptor
#=========================================================================
sub dump_descriptor_0x5b {
    my $desc = shift;
    printf "      (multilingual_network_name_descriptor)\n";
    while (0 < $desc->GetRemainBytesOfDescriptor()) {
        print  "      ISO_639_language_code "; dump_ISO639($desc->GetBytes(3));
        my $length = $desc->GetByte();
        printf "      network_name_length   %d\n", $length;
        printf "      network_name          ";
        dump_string($desc->GetBytes($length));
    }
}

#=========================================================================
# 0x5c : multilingual_bouquet_name_descriptor
#=========================================================================
sub dump_descriptor_0x5c {
    my $desc = shift;
    printf "      (multilingual_bouquet_name_descriptor)\n";
    while (0 < $desc->GetRemainBytesOfDescriptor()) {
        print  "      ISO_639_language_code "; dump_ISO639($desc->GetBytes(3));
        my $length = $desc->GetByte();
        printf "      bouquet_name_length   %d\n", $length;
        printf "      bouquet_name          ";
        dump_string($desc->GetBytes($length));
    }
}

#=========================================================================
# 0x5d : multilingual_service_name_descriptor
#=========================================================================
sub dump_descriptor_0x5d {
    my $desc = shift;
    printf "      (multilingual_service_name_descriptor)\n";
    while (0 < $desc->GetRemainBytesOfDescriptor()) {
        print  "      ISO_639_language_code "; dump_ISO639($desc->GetBytes(3));
        my $provider_length = $desc->GetByte();
        printf "      service_provider_name_length %d\n", $provider_length;
        printf "      service_provider_name        ";
        dump_string($desc->GetBytes($provider_length));
        my $service_length = $desc->GetByte();
        printf "      service_name_length %d\n", $service_length;
        printf "      service_name        ";
        dump_string($desc->GetBytes($service_length));
    }
}

#=========================================================================
# 0x5e : multilingual_component_descriptor
#=========================================================================
sub dump_descriptor_0x5e {
    my $desc = shift;
    printf "      (multilingual_component_descriptor)\n";
    printf "      component_tag 0x%02X\n", $desc->GetByte();
    while (0 < $desc->GetRemainBytesOfDescriptor()) {
        print  "      ISO_639_language_code "; dump_ISO639($desc->GetBytes(3));
        my $length = $desc->GetByte();
        printf "      text_length %d\n", $length;
        printf "      textt_name  ";
        dump_string($desc->GetBytes($length));
    }
}

#=========================================================================
# 0x5f : private_data_specifier_descriptor
#=========================================================================
sub dump_descriptor_0x5f {
    my $desc = shift;
    my $pds  = $desc->Get(32);
    printf "      private_data_specifier 0x%08X\n", $pds;
    return $pds;
}

#=========================================================================
# 0x60 : service_move_descriptor
#=========================================================================
sub dump_descriptor_0x60 {
    my $desc = shift;
    printf "      (service_move_descriptor)\n";
    printf "      new_original_network_id 0x%04X\n", $desc->GetWord();
    printf "      new_transport_stream_id 0x%04X\n", $desc->GetWord();
    printf "      new_servicd_id          0x%04X\n", $desc->GetWord();
}

#=========================================================================
# 0x61 : short_smoothing_buffer_descriptor
#=========================================================================
sub dump_descriptor_0x61 {
    my $desc = shift;
    printf "      (short_smoothing_buffer_descriptor)\n";
    printf "      sb_size      %d\n", $desc->Get(2);
    printf "      sb_leak_size %d\n", $desc->Get(8);
    dump_descriptor_data_in_hex("      reserved ", $desc);
}

#=========================================================================
# 0x62 : frequency_list_descriptor
#=========================================================================
sub dump_descriptor_0x62 {
    my $desc = shift;
    $desc->Skip(6);
    printf "      (frequency_list_descriptor)\n";
    printf "      coding_type %d \n", $desc->Get(2);
    while (0 < $desc->GetRemainBytesOfDescriptor()) {
        printf "      centre_frequency %d\n", $desc->Get(32);
    }
}

#=========================================================================
# 0x63 : partial_transport_stream_descriptor
#=========================================================================
sub dump_descriptor_0x63 {
    my $desc = shift;
    printf "      (partial_transport_stream_descriptor)\n";
    printf "      DVB_reserved_future_use          %d\n", $desc->Get( 2);
    printf "      peak_rate                        %d\n", $desc->Get(22);
    printf "      DVB_reserved_future_use          %d\n", $desc->Get( 2);
    printf "      minimum_overall_smoothing_rate   %d\n", $desc->Get(22);
    printf "      DVB_reserved_future_use          %d\n", $desc->Get( 2);
    printf "      maximum_overall_smoothing_buffer %d\n", $desc->Get(14);
}

#=========================================================================
# 0x64 : data_broadcast_descriptor
#=========================================================================
sub dump_descriptor_0x64 {
    my $desc = shift;
    printf "      (data_broadcast_descriptor)\n";
    printf "      data_broadcast_id 0x%04X\n", $desc->GetWord();
    printf "      component_tag     0x%02X\n", $desc->GetByte();
    my $selector_length = $desc->GetByte();
    printf "      selector_length   %d\n", $selector_length;
    printf "      selector_byte     ";
    dump_hex($desc->GetBytes($selector_length));
    print  "      ISO_639_language_code "; dump_ISO639($desc->GetBytes(3));
    my $text_length = $desc->GetByte();
    printf "      text_length       %d\n", $text_length;
    print  "      text_char         ";
    dump_string($desc->GetBytes($text_length));
}

#=========================================================================
# 0x65 : scrambling_descriptor
#=========================================================================
sub dump_descriptor_0x65 {
    my $desc = shift;
    printf "      (scrambling_descriptor)\n";
    printf "      scrambling_mode %d\n", $desc->GetByte();
}

#=========================================================================
# 0x66 : data_broadcast_id_descriptor
#=========================================================================
sub dump_descriptor_0x66 {
    my $desc = shift;
    printf "      data_broadcast_id 0x%04X\n", $desc->GetWord();
    while (0 < $desc->GetRemainBytesOfDescriptor()) {
        printf "      id_selector_byte 0x%02X\n", $desc->GetByte();
    }
}

#=========================================================================
# 0x67 : transport_stream_descriptor
#=========================================================================
sub dump_descriptor_0x67 {
    my $desc = shift;
    printf "      (transport_stream_descriptor)\n";
    dump_descriptor_data_in_hex("      byte ", $desc);
}

#=========================================================================
# 0x68 : DSNG_descriptor
#=========================================================================
sub dump_descriptor_0x68 {
    my $desc = shift;
    printf "      (DSNG_descriptor)\n";
    dump_descriptor_data_in_hex("      byte ", $desc);
}

#=========================================================================
# 0x69 : PDC_descriptor
#=========================================================================
sub dump_descriptor_0x69 {
    my $desc = shift;
    printf "      (PDC_descriptor)\n";
                              $desc->Skip(4);
    printf "      day    %d\n", $desc->Get (5);
    printf "      month  %d\n", $desc->Get (4);
    printf "      hour   %d\n", $desc->Get (5);
    printf "      minute %d\n", $desc->Get (6);
}

#=========================================================================
# 0x6a : AC-3_descriptor
#=========================================================================
sub dump_descriptor_0x6a {
    my $desc = shift;
    printf "      (AC-3_descriptor)\n";
    dump_descriptor_data_in_hex("      ", $desc);
}

#=========================================================================
# 0x6b : ancillary data descriptor
#=========================================================================
sub dump_descriptor_0x6b {
    my $desc = shift;
    printf "      (ancillary data descriptor)\n";
    printf "      ancillary_data_identifier %d\n", $desc->GetByte();
}

#=========================================================================
# 0x6c : cell_list_descriptor
#=========================================================================
sub dump_descriptor_0x6c {
    my $desc = shift;
    printf "      (cell list descriptor)\n";
    while (0 < $desc->GetRemainBytesOfDescriptor()) {
        printf "      cell_id %d\n", $desc->GetWord();
        printf "      cell_latitude  %d\n", $desc->GetWord();
        printf "      cell_longitude %d\n", $desc->GetWord();
        printf "      cell_extent_of_latitude  %d\n", $desc->Get(12);
        printf "      cell_extent_of_longitude %d\n", $desc->Get(12);
        my $length = $desc->GetByte();
        printf "      subcell_info_loop_length %d\n", $length;
        for (my $i = 0; $i < $length; ++$i) {
            printf "      cell_id_extension %d\n", $desc->GetByte();
            printf "      subcell_latitude  %d\n", $desc->GetWord();
            printf "      subcell_longitude %d\n", $desc->GetWord();
            printf "      subcell_extent_of_latitude  %d\n", $desc->Get(12);
            printf "      subcell_extent_of_longitude %d\n", $desc->Get(12);
        }
    }
}

#=========================================================================
# 0x6d : cell_frequency_link_descriptor
#=========================================================================
sub dump_descriptor_0x6d {
    my $desc = shift;
    printf "      (cell_frequency_link_descriptor)\n";
    while (0 < $desc->GetRemainBytesOfDescriptor()) {
        printf "      cell_id   0x%04X \n", $desc->GetWord();
        printf "      frequency %d     \n", $desc->Get(32);
        my $subcell_info_loop_length =      $desc->GetByte();
        printf "      subcell_info_loop_length %d \n", $subcell_info_loop_length;
        for (my $i = 0; $i < $subcell_info_loop_length; ++$i) {
            printf "        cell_id_extension    %d \n", $desc->GetByte();
            printf "        transposer_frequency %d \n", $desc->Get(32);
        }
    }
}

#=========================================================================
# 0x6e : announcement_support_descriptor
#=========================================================================
sub dump_descriptor_0x6e {
    my $desc = shift;
    printf "      (announcement_support_descriptor)\n";
    printf "      announcement_support_indicator %d\n", $desc->GetWord();
    while (0 < $desc->GetRemainBytesOfDescriptor()) {
        printf "      SS?                 %d\n", $desc->Get(4);
        printf "      reserved_future_use %d\n", $desc->Get(1);
        my $reftype =                            $desc->Get(3);
        printf "      reference_type      %d\n", $reftype;
        if (0x01 == $reftype ||
            0x02 == $reftype ||
            0x03 == $reftype) {
            printf "      original_network_id 0x%04X\n", $desc->GetWord();
            printf "      transport_stream_id 0x%04X\n", $desc->GetWord();
            printf "      service_id          0x%04X\n", $desc->GetWord();
            printf "      component_tag       0x%02X\n", $desc->GetByte();
        }
    }
}

#=========================================================================
# 0x6f : application_signalling_descriptor
#=========================================================================
sub dump_descriptor_0x6f {
    my $desc = shift;
    printf "      (application_signalling_descriptor)\n";
    dump_descriptor_data_in_hex("      ", $desc);
}

#=========================================================================
# 0x70 : adaptation_field_data_descriptor
#=========================================================================
sub dump_descriptor_0x70 {
    my $desc = shift;
    printf "      (adaptation_field_data_descriptor)\n";
    printf "      adaptation_field_data_identifier %d\n", $desc->GetByte();
}

#=========================================================================
# 0x72 : service_availability_descriptor
#=========================================================================
sub dump_descriptor_0x72 {
    my $desc = shift;
    printf "      (service_availability_descriptor)\n";
    printf "      availability_flag %d \n", $desc->Get(1);
                                          $desc->Skip(7);
    while (0 < $desc->GetRemainBytesOfDescriptor()) {
        printf "      cell_id 0x%04X \n", $desc->GetWord();
    }
}

#=========================================================================
# 0x76 : content_identifier_descriptor
#=========================================================================
sub dump_descriptor_0x76 {
    my $desc = shift;
    printf "      (content_identifier_descriptor)\n";
    while (0 < $desc->GetRemainBytesOfDescriptor()) {
        printf "      crid_type     %d\n", $desc->Get(6);
        my $location =                   $desc->Get(2);
        printf "      crid_location %d\n", $location;
        if (0 == $location) {
            my $length = $desc->GetByte();
            printf "      crid_length   %d\n", $length;
            printf "      crid          ";
            for (my $i = 0; $i < $length; ++$i) {
                printf "%02X ", $desc->GetByte();
            }
            printf "\n";
        }
        elsif (1 == $location) {
            printf "      crid_ref      %d\n", $desc->GetWord();
        }
    }
}

#=========================================================================
# 0x79 : S2 satellite delivery system descriptor
#=========================================================================
sub dump_descriptor_0x79 {
    my $desc = shift;
    printf "      (S2_satellite_delivery_system_descriptor)\n";
    my $selector =                                         $desc->Get(1);
    printf "      scrambling_sequence_selector      %d\n", $selector;
    my $flag =                                             $desc->Get(1);
    printf "      multiple_input_stream_flag        %d\n", $flag;
    printf "      backwards_compatibility_indicator %d\n", $desc->Get(1);
    printf "      reserved_future_use               %d\n", $desc->Get(5);
    if (1 == $selector) {
        printf "      Reserved                          %d\n", $desc->Get(6);
        printf "      scrambling_sequence_index         %d\n", $desc->Get(18);
    }
    if (1 == $flag) {
        printf "      input_stream_identifier           %d\n", $desc->GetByte();
    }
}

#=========================================================================
# 0x7a : enhanced_AC-3_descriptor
#=========================================================================
sub dump_descriptor_0x7a {
    my $desc = shift;
    printf "      (enhanced_AC-3_descriptor)\n";
    my $component_type_flag = $desc->Get(1);
    my $bsid_flag           = $desc->Get(1);
    my $mainid_flag         = $desc->Get(1);
    my $asvc_flag           = $desc->Get(1);
    my $mixinfoexists       = $desc->Get(1);
    my $substream1_flag     = $desc->Get(1);
    my $substream2_flag     = $desc->Get(1);
    my $substream3_flag     = $desc->Get(1);
    printf "      component_type_flag %d\n", $component_type_flag;
    printf "      bsid_flag           %d\n", $bsid_flag;
    printf "      mainid_flag         %d\n", $mainid_flag;
    printf "      asvc_flag           %d\n", $asvc_flag;
    printf "      mixinfoexists       %d\n", $mixinfoexists;
    printf "      substream1_flag     %d\n", $substream1_flag;
    printf "      substream2_flag     %d\n", $substream2_flag;
    printf "      substream3_flag     %d\n", $substream3_flag;
    if (1 == $component_type_flag) {
    printf "      component_type      %d\n", $desc->GetByte();
    }
    if (1 == $bsid_flag) {
        printf "      bsid                %d\n", $desc->GetByte();
    }
    if (1 == $mainid_flag) {
        printf "      mainid              %d\n", $desc->GetByte();
    }
    if (1 == $asvc_flag) {
        printf "      asvc                %d\n", $desc->GetByte();
    }
    if (1 == $substream1_flag) {
        printf "      substream1          %d\n", $desc->GetByte();
    }
    if (1 == $substream2_flag) {
        printf "      substream2          %d\n", $desc->GetByte();
    }
    if (1 == $substream2_flag) {
        printf "      substream2          %d\n", $desc->GetByte();
    }
    dump_descriptor_data_in_hex("      additinal_info_byte ", $desc);
}

#=========================================================================
# 0x7b : DTS_audio_stream_descriptor
#=========================================================================
sub dump_descriptor_0x7b {
    my $desc = shift;
    printf "      (DTS_audio_stream_descriptor)\n";
    printf "      sample_rate_code       %d\n", $desc->Get( 4);
    printf "      bit_rate_code          %d\n", $desc->Get( 6);
    printf "      nblks                  %d\n", $desc->Get( 7);
    printf "      fsize                  %d\n", $desc->Get(14);
    printf "      surround_mode          %d\n", $desc->Get( 6);
    printf "      lfe_flag               %d\n", $desc->Get( 1);
    printf "      extended_surround_flag %d\n", $desc->Get( 2);
    dump_descriptor_data_in_hex("      additinal_info_byte ", $desc);
}

#=========================================================================
# 0x7c : AAC_descriptor
#=========================================================================
sub dump_descriptor_0x7c {
    my $desc = shift;
    printf "      (AAC_descriptor)\n";
    printf "      profile_and_level %d\n", $desc->GetByte();
    if (0 < $desc->GetRemainBytesOfDescriptor()) {
        my $flag = $desc->Get(1);
        printf "      AAC_type_flag     %d\n", $flag;
        printf "      reserved          %d\n", $desc->Get(7);
        if (1 == $flag) {
            printf "      AAC_type          %d\n", $desc->GetByte();
        }
        dump_descriptor_data_in_hex("      additinal_info_byte ", $desc);
    }
}

#=========================================================================
# 0x7e : FTA_content_management_descriptor
#=========================================================================
sub dump_descriptor_0x7e {
    my $desc = shift;
    printf "      (FTA_content_management_descriptor)\n";
    printf "      user_defined                         %d\n", $desc->Get(1);
    printf "      reserved_future_use                  %d\n", $desc->Get(3);
    printf "      do_not_scramble                      %d\n", $desc->Get(1);
    printf "      control_remmote_access_over_internet %d\n", $desc->Get(2);
    printf "      do_not_apply_revocation              %d\n", $desc->Get(1);
}

#=========================================================================
# 0x7f - 0x00 : image_icon_descriptor
#=========================================================================
sub dump_desc_ext_0x00 {
    my $desc = shift;
    printf "      (image_icon_descriptor)\n";
    my $desc_num      = $desc->Get(4);
    my $last_desc_num = $desc->Get(4);
    my $reserved      = $desc->Get(5);
    my $icon_id       = $desc->Get(3);
    printf "      descriptor_number      %d\n", $desc_num;
    printf "      last_descriptor_number %d\n", $last_desc_num;
    printf "      reserved_future_use    %d\n", $reserved;
    printf "      icon_id                %d\n", $icon_id;
    if (0x00 == $desc_num) {
        my $mode = $desc->Get(2);
        my $flag = $desc->Get(1);
        printf "      icon_transport_mode %d\n", $mode;
        printf "      position_flag       %d\n", $flag;
        if (0x01 == $flag) {
            printf "      coordinate_system      %d\n", $desc->Get(3);
            printf "      reserved_future_use    %d\n", $desc->Get(2);
            printf "      icon_horizontal_origin %d\n", $desc->Get(12);
            printf "      icon_vertical_origin   %d\n", $desc->Get(12);
        } else {
            printf "      reserved_future_use    %d\n", $desc->Get(5);
        }
        my $type_length = $desc->GetByte();
        printf "      icon_type_length %d\n", $type_length;
        printf "      icon_type_char ";
        dump_hex($desc->GetBytes($type_length));
        if (0x00 == $mode) {
            my $data_length = $desc->GetByte();
            printf "      icon_data_length %d\n", $data_length;
            printf "      icon_data_byte   ";
            dump_hex($desc->GetBytes($data_length));
        }
        elsif (0x01 == $mode) {
            my $url_length = $desc->GetByte();
            printf "      url_length %d\n", $url_length;
            printf "      url_char   ";
            dump_string($desc->GetBytes($url_length));
        }
    } else {
        my $length = $desc->GetByte();
        printf "      icon_data_length %d\n", $length;
        printf "      icon_data_byte   ";
        dump_hex($desc->GetBytes($length));
    }
}

#=========================================================================
# 0x7f - 0x02 : CP_descriptor
#=========================================================================
sub dump_desc_ext_0x02 {
    my $desc = shift;
    printf "      (CP_descriptor)\n";
    printf "      CP_system_id 0x%04X\n", $desc->GetWord();
    printf "      reserved     %d\n",     $desc->Get( 3);
    printf "      CP_PID       0x%04X\n", $desc->Get(13);
    dump_descriptor_data_in_hex("      private_data_byte ", $desc);
}

#=========================================================================
# 0x7f - 0x03 : CP_identifier_descriptor
#=========================================================================
sub dump_desc_ext_0x03 {
    my $desc = shift;
    printf "      (CP_identifier_descriptor)\n";
    while (0 < $desc->GetRemainBytesOfDescriptor()) {
        printf "      CP_system_id 0x%04X\n", $desc->GetWord();
    }
}

#=========================================================================
# 0x7f - 0x04 : T2_delivery_system_descriptor
#=========================================================================
sub dump_desc_ext_0x04 {
    my $desc = shift;
    printf "      (T2_delivery_system_descriptor)\n";
    printf "      plp_id                   %d\n", $desc->GetByte();
    printf "      T2_system_id             %d\n", $desc->GetWord();
    if (4 < $desc->GetRemainBytesOfDescriptor()) {
        printf "      SISO/MISO                %d\n", $desc->Get(2);
        printf "      bandwidth                %d\n", $desc->Get(4);
        printf "      reserved_future_use      %d\n", $desc->Get(2);
        printf "      guard_interval           %d\n", $desc->Get(3);
        printf "      transmission_mode        %d\n", $desc->Get(3);
        printf "      other_frequency_flag     %d\n", $desc->Get(1);
        my $tfs_flag =                                $desc->Get(1);
        printf "      tsf_flag                 %d\n", $tfs_flag;
        while (0 < $desc->GetRemainBytesOfDescriptor()) {
            printf "      cell_id                  %d\n", $desc->GetWord();
            if (1 == $tfs_flag) {
                my $loop_len =                                $desc->GetByte();
                printf "      frequency_loop_length    %d\n", $loop_len;
                for (my $i = 0; $i < $loop_len; ++$i) {
                    printf "      center_frequency         %d\n", $desc->Get(32);
                }
            }
            else {
                printf "      center_frequency         %d\n", $desc->Get(32);
            }
            my $subcell_len =                             $desc->GetByte();
            printf "      subcell_info_loop_length %d\n", $subcell_len;
            for (my $k = 0; $k < $subcell_len; ++$k) {
                printf "      cell_id_extension        %d\n", $desc->GetByte();
                printf "      transposer_frequency     %d\n", $desc->Get(32);
            }
        }
    }
}

#=========================================================================
# 0x7f - 0x08 : message_descriptor
#=========================================================================
sub dump_desc_ext_0x08 {
    my $desc = shift;
    printf "      (message_descriptor)\n";
    printf "      message_id            %d\n", $desc->GetByte();
    print  "      ISO_639_language_code "; dump_ISO639($desc->GetBytes(3));
    my $text_len = $desc->GetRemainBytesOfDescriptor();
    printf  "      text_char            (%d) ", $text_len;
    dump_string($desc->GetBytes($text_len));
}

#=========================================================================
# 0x7f - 0x0b : service_relocated_descriptor
#=========================================================================
sub dump_desc_ext_0x0b {
    my $desc = shift;
    printf "      (service_relocated_descriptor)\n";
    printf "      old_original_network_id 0x%04X\n", $desc->GetWord();
    printf "      old_transport_stream_id 0x%04X\n", $desc->GetWord();
    printf "      old_service_id          0x%04X\n", $desc->GetWord();
}

#=========================================================================
# 0x7f - 0x0d : C2_delivery_system_descriptor
#=========================================================================
sub dump_desc_ext_0x0d {
    my $desc = shift;
    printf "      (C2_delivery_system_descriptor)\n";
    printf "      plp_id                      %d\n", $desc->GetByte();
    printf "      data_slice_id               %d\n", $desc->GetByte();
    printf "      C2_tuning_frequency         %d\n", $desc->Get(32);
    printf "      C2_tuning_frequency_type    %d\n", $desc->Get( 2);
    printf "      active_OFDM_symbol_duration %d\n", $desc->Get( 3);
    printf "      guard_interval              %d\n", $desc->Get( 3);
}

##########################################################################
#
# LCN
#
##########################################################################

#=========================================================================
# Generic 1-5-10 format LCN descriptor
#=========================================================================
sub dump_descriptor_generic_1_5_10_lcn {
    my $desc = shift;
    printf "      (1-5-10 format LCN descriptor)\n";
    while (0 < $desc->GetRemainBytesOfDescriptor()) {
        printf "      service_id           0x%04X \n", $desc->GetWord();
        printf "      visible_service_flag %d\n",      $desc->Get ( 1);
                                                     $desc->Skip( 5);
        printf "      lcn                  %d\n",      $desc->Get (10);
    }
}

#=========================================================================
# Generic 6-10 format LCN descriptor
#=========================================================================
sub dump_descriptor_generic_6_10_lcn {
    my $desc = shift;
    printf "      (6-10 format LCN descriptor)\n";
    while (0 < $desc->GetRemainBytesOfDescriptor()) {
        printf "      service_id 0x%04X \n", $desc->GetWord();
                                                     $desc->Skip( 6);
        printf "      lcn        %d\n",      $desc->Get (10);
    }
}

#=========================================================================
# Generic 16 format LCN descriptor
#=========================================================================
sub dump_descriptor_generic_16_lcn {
    my $desc = shift;
    printf "      (16 format LCN descriptor)\n";
    while (0 < $desc->GetRemainBytesOfDescriptor()) {
        printf "      service_id 0x%04X \n", $desc->GetWord();
        printf "      lcn        %d\n",      $desc->GetWord(); #16
    }
}

#=========================================================================
# Nordig V1 LCN descriptor (1-1-14)
#=========================================================================
sub dump_descriptor_nordig_v1_lcn {
    my $desc = shift;
    printf "      (Nordig V1 LCN descriptor)\n";
    while (0 < $desc->GetRemainBytesOfDescriptor()) {
        printf "      service_id           0x%04X\n", $desc->GetWord();
        printf "      visible_service_flag %d\n"    , $desc->Get ( 1);
                                                      $desc->Skip( 1);
        printf "      lcn                  %d\n",     $desc->Get (14);
    }
}

#=========================================================================
# Nordig V2 LCN descriptor
#=========================================================================
sub dump_descriptor_nordig_v2_lcn {
    my $desc = shift;
    printf "      (Nordig V2 LCN descriptor)\n";
    while (0 < $desc->GetRemainBytesOfDescriptor()) {
        printf "      channel_list_id %d\n", $desc->GetByte();
        my $name_length = $desc->GetByte();
        printf "      channel_list_name(%d) ", $name_length;
        dump_string($desc->GetBytes($name_length));
        printf "      country_code "; dump_ISO639($desc->GetBytes(3));
        my $desc_length = $desc->GetByte();
        printf "      descriptor_length  %d\n", $desc_length;
        for (my $i = 0; $i < $desc_length / 4; ++$i) {
            printf "        service_id           0x%04X\n", $desc->GetWord();
            printf "        visible_service_flag %d\n",     $desc->Get ( 1);
                                                            $desc->Skip( 1);
            printf "        lcn                  %d\n",     $desc->Get (14);
        }
    }
}

#=========================================================================
# MYS/SGP V2 LCN descriptor
#=========================================================================
sub dump_descriptor_MYS_SGP_v2_lcn {
    my $desc = shift;
    printf "      (MYS/SGP V2 LCN descriptor)\n";
    while (0 < $desc->GetRemainBytesOfDescriptor()) {
        printf "      channel_list_id %d\n", $desc->GetByte();
        my $name_length = $desc->GetByte();
        printf "      channel_list_name(%d) ", $name_length;
        dump_string($desc->GetBytes($name_length));
        printf "      country_code "; dump_ISO639($desc->GetBytes(3));
        my $desc_length = $desc->GetByte();
        printf "      descriptor_length  %d\n", $desc_length;
        for (my $i = 0; $i < $desc_length / 4; ++$i) {
            printf "        service_id           0x%04X\n", $desc->GetWord();
            printf "        visible_service_flag %d\n",     $desc->Get ( 1);
                                                            $desc->Skip( 5);
            printf "        lcn                  %d\n",     $desc->Get (10);
        }
    }
}

#=========================================================================
# HD simulcast LCN
#=========================================================================
sub dump_descriptor_hd_simulcast_lcn {
    my $desc = shift;
    printf "      (HD simulcast LCN descriptor)\n";
    while (0 < $desc->GetRemainBytesOfDescriptor()) {
        printf "      service_id           0x%04X \n", $desc->GetWord();
        printf "      visible_service_flag %d\n",      $desc->Get ( 1);
                                                       $desc->Skip( 5);
        printf "      lcn                  %d\n",      $desc->Get (10);
    }
}

##########################################################################
#
# OTHER
#
##########################################################################

#=========================================================================
# ci_protection_descriptor
#=========================================================================
sub dump_descriptor_ci_protection {
    my $desc = shift;
    printf "      (ci_protection_descriptor)\n";
    printf "      free_ci_mode_flag %d \n", $desc->Get(1);
    my $match_brand_flag =                $desc->Get(1);
    printf "      match_brand_flag  %d \n", $match_brand_flag;
                                          $desc->Skip(6);
    if (1 == $match_brand_flag) {
        my $number_of_entries = $desc->GetByte();
        for (my $i = 0; $i < $number_of_entries; ++$i) {
            printf "      cicam_brand_identifier 0x%04X\n", $desc->GetWord();
        }
    }
    dump_descriptor_data_in_hex("      private_data_byte ", $desc);
}

#=========================================================================
# NDS SERVICE ORDER LIST
#=========================================================================
sub dump_descriptor_nds_service_order_list {
    my $desc = shift;
    print "      (service_order_list)\n";
    while (0 < $desc->GetRemainBytesOfDescriptor()) {
        printf "      service_id    0x%04X\n", $desc->GetWord();
        printf "      general_order %d\n",     $desc->Get(12);
        printf "      order_by_type %d\n",     $desc->Get(12);
    }
}

#=========================================================================
# service_attribute_descriptor
#=========================================================================
sub dump_descriptor_service_attribute {
    my $desc = shift;
    printf "      (service_attribute_descriptor)\n";
    while (0 < $desc->GetRemainBytesOfDescriptor()) {
        printf "      service_id           0x%04X\n", $desc->GetWord();
                                                    $desc->Skip(6);
        printf "      numeric_section_flag %d\n",     $desc->Get (1);
        printf "      visible_service_flag %d\n",     $desc->Get (1);
    }
}

#=========================================================================
# channel descriptor 3 (Polsat)
#=========================================================================
sub dump_descriptor_channel_3 {
    my $desc = shift;
    printf "      (channel_descriptor_3)\n";
    while (0 < $desc->GetRemainBytesOfDescriptor()) {
        printf "      service_id    0x%04X\n", $desc->GetWord();
        printf "      channel_id    0x%04X\n", $desc->GetWord();
        printf "      cp_service_id 0x%04X\n", $desc->GetWord();
    }
}

##########################################################################
#
# DUMP TOOL
#
##########################################################################

#=========================================================================
# dump data in hex
#=========================================================================
sub dump_descriptor_data_in_hex {
    my $head = shift;
    my $desc = shift;
    printf "%s(%d) ", $head, $desc->GetRemainBytesOfDescriptor();
    while (0 < $desc->GetRemainBytesOfDescriptor()) {
        printf "%02X ", $desc->GetByte();
    }
    printf "\n";
}

#=========================================================================
# dump ISO639
#=========================================================================
sub dump_ISO639 {
    print chr($_[0]) . chr($_[1]) . chr($_[2]) . "\n";
}

#=========================================================================
# dump DVB-SI string
#=========================================================================
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

#=========================================================================
# dump in HEX
#=========================================================================
sub dump_hex {
    foreach my $c (@_) {
        printf "%02X ", $c;
    }
    print "\n";
}

#=========================================================================
# dump 4bit BCD
#=========================================================================
sub dump_4bitBCD {
    my $value  = shift;
    my $digits = shift;
#   use constant numeric =>
#       [ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' ];
    my $str = "";
    for (my $i = $value; 0 < $i; $i = $i >> 4) {
        $str = numeric->[$i & 0xF] . $str;
    }
    if (defined($digits) && length($str) < $digits) {
        for (my $i = 0 ; $i < $digits - length($str) ; ++$i) {
            print "0";
        }
        print "$str\n";
    } else {
        printf "%s\n", ("" ne $str) ? $str : "0";
    }
}

#=========================================================================
# dump linkage type
#=========================================================================
sub dump_linkage_type {
    my $type = shift;
    use constant linkage_name => [
        "reserved for future use",                   # 0x00
        "information service",                       # 0x01
        "EPG service",                               # 0x02
        "CA replacement service",                    # 0x03
        "TS containing complete Network/Bouquet SI", # 0x04
        "service replacement service",               # 0x05
        "data broadcast service",                    # 0x06
        "RCS Map",                                   # 0x07
        "mobile hand-over",                          # 0x08
        "System Software Update Service",            # 0x09
        "TS containing SSU BAT or NIT",              # 0x0A
        "IP/MAC Notification Service",               # 0x0B
        "TS conaining INT BAT or NIT",               # 0x0C
        "event linkage",                             # 0x0D
        "extended event linkage",                    # 0x0E
    ];
    if ($type <= 0x0e) {
        print linkage_name->[$type];
    } elsif (0x0f <= $type && $type <= 0x7f) {
        print "reserved for future use";
    } elsif (0x80 <= $type && $type <= 0xfe) {
        print "user defined";
    } elsif (0xff == $type) {
        print "reserved for future use";
    } else {
        printf "undefined 0x%02X", $type;
    }
}

#=========================================================================
# dump Bandwidth
#=========================================================================
sub dump_bandwidth {
    use constant bandwidth => [
        '8MHz', '7MHz', '6MHz', '5MHz', '-', '-', '-', '-',
    ];
    print bandwidth->[$_[0]] . "($_[0])\n";
}

#=========================================================================
# dump UTC time
#=========================================================================
sub dump_utc_time {
    my $mjd = shift;
    my $utc = shift;
#   use constant numeric =>
#       [ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' ];
    printf "%s %s%s:%s%s:%s%s\n",
           get_ymd_from_mjd($mjd),
           numeric->[($utc & 0xF00000) >> 20],
           numeric->[($utc & 0x0F0000) >> 16],
           numeric->[($utc & 0x00F000) >> 12],
           numeric->[($utc & 0x000F00) >>  8],
           numeric->[($utc & 0x0000F0) >>  4],
           numeric->[($utc & 0x00000F)];
}

#=========================================================================
# dump MM:SS
#=========================================================================
sub dump_mmss {
    my $mmss = shift;
#   use constant numeric =>
#       [ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' ];
    printf "%s%s:%s%s\n",
           numeric->[($mmss & 0x00F000) >> 12],
           numeric->[($mmss & 0x000F00) >>  8],
           numeric->[($mmss & 0x0000F0) >>  4],
           numeric->[($mmss & 0x00000F)];
}

#=========================================================================
# dump HH:MM:SS
#=========================================================================
sub dump_hhmmss {
    my $hhmmss = shift;
#   use constant numeric =>
#       [ '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' ];
    printf "%s%s:%s%s:%s%s\n",
           numeric->[($hhmmss & 0xF00000) >> 20],
           numeric->[($hhmmss & 0x0F0000) >> 16],
           numeric->[($hhmmss & 0x00F000) >> 12],
           numeric->[($hhmmss & 0x000F00) >>  8],
           numeric->[($hhmmss & 0x0000F0) >>  4],
           numeric->[($hhmmss & 0x00000F)];
}

##########################################################################
#
# TOOL
#
##########################################################################

sub get_start_index_of_payload {
    my $adaptation_field_control = shift;
    my $ref_data = shift;

    if (3 == $adaptation_field_control) {
        my @data = @$ref_data; # de-reference
        return 4 + 1 + $data[4];
    } else {
        return 4;
    }
}

#=========================================================================
# get PID list from PAT
#=========================================================================
sub get_pid_list_from_pat {
    my %pat = @_; # hash

    my $ref_program_list = $pat{ program_list }; # reference to array
    my @program_list = @$ref_program_list;       # de-reference

    my @pid_list = ();
    my $ref_program;
    foreach $ref_program (@program_list) {       # reference to hash
        if (0 != $ref_program->{ program_number}) {
            push(@pid_list, $ref_program->{ PID });
        }
    }

    return @pid_list;
}

#=========================================================================
# get NIT PID from PAT
#=========================================================================
sub get_nit_pid_from_pat {
    my %pat = @_; # hash

    my $ref_program_list = $pat{ program_list }; # reference to array
    my @program_list = @$ref_program_list;       # de-reference

    my @pid_list = ();
    my $ref_program;
    foreach $ref_program (@program_list) {       # reference to hash
        if (0 == $ref_program->{ program_number}) {
            return $ref_program->{ PID };
        }
    }

    return undef; # not found.
}

#=========================================================================
# Modified Julian Day
#=========================================================================
sub get_ymd_from_mjd {
    my $mjd = shift;

    my $y0 = int(($mjd - 15078.2) / 365.25);
    my $m0 = int(($mjd - 14956.1 - int($y0 * 365.25)) / 30.6001);
    my $d  = $mjd - 14956 - int($y0 * 365.25) - int($m0 * 30.6001);
    my $k  = (14 == $m0 || 15 == $m0) ? 1 : 0;
    my $y  = $y0 + $k;
    my $m  = $m0 - 1 - ($k * 12);

    return sprintf("%04d/%02d/%02d", $y + 1900, $m, $d);
}

##########################################################################
#
# CRC32
# from http://forum.videolan.org/viewtopic.php?f=4&t=10664
#
##########################################################################
sub CRC32 {
    my($ref_Data) = shift;

    use constant crc_table => [
        0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9,
        0x130476dc, 0x17c56b6b, 0x1a864db2, 0x1e475005,
        0x2608edb8, 0x22c9f00f, 0x2f8ad6d6, 0x2b4bcb61,
        0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd,
        0x4c11db70, 0x48d0c6c7, 0x4593e01e, 0x4152fda9,
        0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75,
        0x6a1936c8, 0x6ed82b7f, 0x639b0da6, 0x675a1011,
        0x791d4014, 0x7ddc5da3, 0x709f7b7a, 0x745e66cd,
        0x9823b6e0, 0x9ce2ab57, 0x91a18d8e, 0x95609039,
        0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5,
        0xbe2b5b58, 0xbaea46ef, 0xb7a96036, 0xb3687d81,
        0xad2f2d84, 0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d,
        0xd4326d90, 0xd0f37027, 0xddb056fe, 0xd9714b49,
        0xc7361b4c, 0xc3f706fb, 0xceb42022, 0xca753d95,
        0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1,
        0xe13ef6f4, 0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d,
        0x34867077, 0x30476dc0, 0x3d044b19, 0x39c556ae,
        0x278206ab, 0x23431b1c, 0x2e003dc5, 0x2ac12072,
        0x128e9dcf, 0x164f8078, 0x1b0ca6a1, 0x1fcdbb16,
        0x018aeb13, 0x054bf6a4, 0x0808d07d, 0x0cc9cdca,
        0x7897ab07, 0x7c56b6b0, 0x71159069, 0x75d48dde,
        0x6b93dddb, 0x6f52c06c, 0x6211e6b5, 0x66d0fb02,
        0x5e9f46bf, 0x5a5e5b08, 0x571d7dd1, 0x53dc6066,
        0x4d9b3063, 0x495a2dd4, 0x44190b0d, 0x40d816ba,
        0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e,
        0xbfa1b04b, 0xbb60adfc, 0xb6238b25, 0xb2e29692,
        0x8aad2b2f, 0x8e6c3698, 0x832f1041, 0x87ee0df6,
        0x99a95df3, 0x9d684044, 0x902b669d, 0x94ea7b2a,
        0xe0b41de7, 0xe4750050, 0xe9362689, 0xedf73b3e,
        0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2,
        0xc6bcf05f, 0xc27dede8, 0xcf3ecb31, 0xcbffd686,
        0xd5b88683, 0xd1799b34, 0xdc3abded, 0xd8fba05a,
        0x690ce0ee, 0x6dcdfd59, 0x608edb80, 0x644fc637,
        0x7a089632, 0x7ec98b85, 0x738aad5c, 0x774bb0eb,
        0x4f040d56, 0x4bc510e1, 0x46863638, 0x42472b8f,
        0x5c007b8a, 0x58c1663d, 0x558240e4, 0x51435d53,
        0x251d3b9e, 0x21dc2629, 0x2c9f00f0, 0x285e1d47,
        0x36194d42, 0x32d850f5, 0x3f9b762c, 0x3b5a6b9b,
        0x0315d626, 0x07d4cb91, 0x0a97ed48, 0x0e56f0ff,
        0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623,
        0xf12f560e, 0xf5ee4bb9, 0xf8ad6d60, 0xfc6c70d7,
        0xe22b20d2, 0xe6ea3d65, 0xeba91bbc, 0xef68060b,
        0xd727bbb6, 0xd3e6a601, 0xdea580d8, 0xda649d6f,
        0xc423cd6a, 0xc0e2d0dd, 0xcda1f604, 0xc960ebb3,
        0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7,
        0xae3afba2, 0xaafbe615, 0xa7b8c0cc, 0xa379dd7b,
        0x9b3660c6, 0x9ff77d71, 0x92b45ba8, 0x9675461f,
        0x8832161a, 0x8cf30bad, 0x81b02d74, 0x857130c3,
        0x5d8a9099, 0x594b8d2e, 0x5408abf7, 0x50c9b640,
        0x4e8ee645, 0x4a4ffbf2, 0x470cdd2b, 0x43cdc09c,
        0x7b827d21, 0x7f436096, 0x7200464f, 0x76c15bf8,
        0x68860bfd, 0x6c47164a, 0x61043093, 0x65c52d24,
        0x119b4be9, 0x155a565e, 0x18197087, 0x1cd86d30,
        0x029f3d35, 0x065e2082, 0x0b1d065b, 0x0fdc1bec,
        0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088,
        0x2497d08d, 0x2056cd3a, 0x2d15ebe3, 0x29d4f654,
        0xc5a92679, 0xc1683bce, 0xcc2b1d17, 0xc8ea00a0,
        0xd6ad50a5, 0xd26c4d12, 0xdf2f6bcb, 0xdbee767c,
        0xe3a1cbc1, 0xe760d676, 0xea23f0af, 0xeee2ed18,
        0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4,
        0x89b8fd09, 0x8d79e0be, 0x803ac667, 0x84fbdbd0,
        0x9abc8bd5, 0x9e7d9662, 0x933eb0bb, 0x97ffad0c,
        0xafb010b1, 0xab710d06, 0xa6322bdf, 0xa2f33668,
        0xbcb4666d, 0xb8757bda, 0xb5365d03, 0xb1f740b4,
    ];

    my $crc = 0xffffffff;
    foreach my $x (@$ref_Data) {
        $crc = ($crc << 8) ^ crc_table->[(($crc >> 24) ^ $x) & 0xff];
    }
    return $crc;
}
