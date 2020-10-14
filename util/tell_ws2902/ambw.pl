#!/usr/bin/perl
use strict;
use Socket;
my ($remote, $port, $iaddr, $paddr, $proto, $line);

# Derived from https://help.ambientweather.net/help/telnet-protocol/

my $weewx_intercept_server = '<WEEWX INTERCEPT SERVER>'; #DNS/IP of WeeWx Intercept Server. Max length 64
my $weewx_intercept_port   = 80;
my $weewx_intercept_user   = undef; # WeeWx Intercept Server HTTP Auth user ?. Max length 40
my $weewx_intercept_pass   = undef; # WeeWx Intercept Server HTTP Auth password ?. Max length 40
my $weewx_intercept_frequency = 60; # Update Interval in seconds. 16 - 600.
my $weewx_intercept_protocol = 0;   # Update format: 0=EC style / 1=WU style
my $weewx_intercept_enabled = 1; # 1 for enable sending updates / 0 for disable


$remote='<WS2902 IP>';
$port = 45000;
$iaddr = inet_aton($remote) || die "bad address: $remote\n";
$paddr = sockaddr_in($port, $iaddr);

$proto = getprotobyname("tcp");
my $sock;
socket($sock, PF_INET, SOCK_STREAM, $proto) || die "socket: $!\n";
connect($sock, $paddr) || die "connect: $!\n";
binmode($sock);
my $r = send_packet($sock, 0x2b, $weewx_intercept_user, $weewx_intercept_pass, $weewx_intercept_server, 'n'.$weewx_intercept_port, 'n'.$weewx_intercept_frequency',0,$weewx_intercept_enabled);
my $r = send_packet($sock, 0x2a);

print "Got back ".length($r)." bytes\n";



sub send_packet {
  my ($s, $cmd_v, @args) = @_;
  my $checksum = 0;
  my $size = 1;
  my $packet = 0xffff;

  my @args_out;
  foreach my $v ($cmd_v,0, @args) {
    push @args_out, packMe($v);
    $size += length($args_out[-1]);
  }
  print "SIZE: $size\n";
  my $sz = packMe($size);
  if (length($sz) > 1) {
    $sz = packMe($size+1);
  }
  $args_out[1] = $sz;

  my $packet_out = join('', @args_out);

  my @out_v = unpack('C*', $packet_out);
  my $cksum = cksum(@out_v);

  syswrite($s,  pack('S', 0xffff). $packet_out.pack('C', $cksum));

  print "Sent: ";
  foreach my $v (unpack('C*', $packet)) {
    printf('0x%x "%s" ', $v,$v);
  }
  print "\n";

  my $buf_1 = undef;
  #sysread($s, $buf_1, 4);
  sysread($s, $buf_1, 256);
  my $l = length($buf_1);

  my $OK = 1;
  my @in_v = unpack('SC*', $buf_1);
  my $in_header = shift(@in_v);

  if ($in_header != 0xffff) {
    print "ERROR in response packet.\n";
    $OK = 0;
  } elsif ($in_v[0] != $cmd_v) {
    printf( "ERROR in command doesn't match out command 0x%x / 0x%x\n", $cmd_v, $in_v[0]);
    $OK = 0;
  } elsif ($in_v[1] != scalar(@in_v)) {
    printf( "ERROR size parameter doesn't match returned value 0x%x / 0x%x\n", $in_v[1], scalar(@in_v));
    $OK = 0;
  }
    
  my $in_sum_sender = pop(@in_v);
  my $in_sum = cksum(@in_v);

  if ( $in_sum != $in_sum_sender) {
    printf("ERROR in response packet.  Checksum mismatch %d != %d\n", $in_sum_sender, $in_sum);
    $OK = 0;
  }
  if ($OK == 1) {
    print "Header and checksum OK\n";
  }

  my ($fixed, $cmd_r, $size_in,@v) = unpack('SCCC*', $buf_1);
  printf("Response HEADER 0x%x CMD 0x%x length %u / %d\n", $fixed, $cmd_r,  $size_in, $l);

  foreach my $v ($cmd_r, @v) {
    printf('0x%x "%s" ', $v,( ($v > 31 && $v < 128) ? chr($v) : $v) );
  }
  print "\n";

  if ($cmd_r == 0x20) {  
    my ($h, $c, $s, $id, $pw, $f, $c) = unpack('SCCC/A*C/A*CC', $buf_1);
    print "WU ID: '$id'\n";
    print "WU PW: '$pw'\n";
    print "FIX: $f\n";
  } elsif ($cmd_r == 0x2a) {  
    my ($h, $c, $s, $id, $pw, $server, $port, $interval, $type, $active) = unpack('SCCC/A*C/A*C/A*nnCCC', $buf_1);
    print "ID: '$id'/'$pw'  $server:$port $interval s T:$type A:$active\n";
  }

  return $buf_1;
}

sub cksum {
  my (@in_v) = @_;
  my $in_sum = 0;
  foreach (@in_v) {
    $in_sum += $_;
  }
  return $in_sum % 256;
}

sub packMe {
  my ($val) = @_;
  my $temp;
  if ($val =~ /^\d+$/) {
    if ($val < 256) {
       $temp = pack('C', $val);
    } elsif ($val < 65536) {
       $temp = pack('n', $val);
    } else {
      die "Unhandled value '$val'";
    }
  } elsif ($val =~ /^n(\d+)$/) {
    $temp = pack('n', $1);
  } else {
    my $str = pack('A*', $val);
    my $ls = length($str);
    my $lv = length($val);
    print "Packing String: '$val' ($lv:$ls)\n";
    my $len = packMe(length($str));
    $temp = $len.$str;
  }
  return $temp;
}
