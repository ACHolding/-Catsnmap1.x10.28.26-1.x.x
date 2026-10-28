#!/bin/sh
# Cat's Nmap 1.1.xv0 — standalone shell/Perl TCP connect scanner
# © AC Kondo 1999–2026
# Scan only systems you own or have explicit permission to test.
# Requires Perl core modules, not Nmap or GNU timeout.
exec perl -x "$0" "$@"
#!perl
use strict;
use warnings;
use Socket qw(getaddrinfo getnameinfo NI_NUMERICHOST SOCK_STREAM SOL_SOCKET SO_ERROR);
use Fcntl qw(F_GETFL F_SETFL O_NONBLOCK);
use IO::Select;
use Getopt::Long qw(GetOptions);
Getopt::Long::Configure("no_ignore_case");
use Time::HiRes qw(time sleep);
use Errno qw(EINPROGRESS EWOULDBLOCK EALREADY ECONNREFUSED EHOSTUNREACH ENETUNREACH);
$|=1;
my $version='1.1.xv0';
my ($spec,$fast,$workers,$timeout,$pn,$banners,$report,$verbose,$help,$ver,$yes) = ('',0,100,1,0,0,'',0,0,0,0);
GetOptions('p=s'=>\$spec,'F'=>\$fast,'T=i'=>\$workers,'t=f'=>\$timeout,'Pn'=>\$pn,'sV'=>\$banners,'o=s'=>\$report,'v'=>\$verbose,'V|version'=>\$ver,'h|help'=>\$help,'y|yes'=>\$yes) or die "Invalid options; use -h\n";
if ($ver) { print "Cat's Nmap $version\n"; exit 0; }
if ($help || !@ARGV) {
 print "Cat's Nmap $version — TCP connect scanner\nUsage: sh 1.1.xv0.sh [options] HOST [HOST ...]\n  -p PORTS   22,80,443 or 1-1024 or - (all ports)\n  -F         common fast ports\n  -T N       concurrency 1-256 (default 100)\n  -t SEC     timeout 0.1-30 (default 1)\n  -Pn        skip ICMP discovery (TCP connect mode always probes targets)\n  -sV        basic plain-text banner sampling (not TLS version detection)\n  -o FILE    save report\n  -v         show closed/filtered ports\n  -y         confirm authorization without prompt\n  -V         version\n  -h         help\nOnly scan hosts you own or have permission to test.\n";
 exit($help?0:2);
}
die "Concurrency must be 1-256\n" unless $workers>=1 && $workers<=256;
die "Timeout must be 0.1-30\n" unless $timeout>=0.1 && $timeout<=30;
my $common='21,22,23,25,53,80,110,143,443,445,587,993,995,3306,3389,5432,5900,6379,8000,8080,8443';
my $quick='21,22,25,53,80,443,445,3389,8080';
$spec=$fast?$quick:($spec||$common);
my %ports;
for my $part (split /,/, $spec,-1) {
 die "Empty port specification\n" unless length $part;
 my ($lo,$hi);
 if ($part eq '-') { ($lo,$hi)=(1,65535); }
 elsif ($part =~ /\A(\d{1,5})-(\d{1,5})\z/) { ($lo,$hi)=($1+0,$2+0); }
 elsif ($part =~ /\A\d{1,5}\z/) { ($lo,$hi)=($part+0,$part+0); }
 else { die "Invalid port specification: $part\n"; }
 die "Port out of range: $part\n" if $lo<1 || $hi>65535 || $lo>$hi;
 $ports{$_}=1 for $lo..$hi;
}
my @ports=sort {$a<=>$b} keys %ports;
if (!$yes) {
 print "Confirm you are authorized to scan these targets [y/N]: ";
 my $answer=<STDIN> // '';
 exit 0 unless $answer =~ /\A\s*y(?:es)?\s*\z/i;
}
my %services=(22=>'ssh',21=>'ftp',25=>'smtp',53=>'domain',80=>'http',110=>'pop3',143=>'imap',443=>'https',445=>'smb',587=>'submission',993=>'imaps',995=>'pop3s',3306=>'mysql',3389=>'rdp',5432=>'postgresql',5900=>'vnc',6379=>'redis',8080=>'http-proxy',8443=>'https-alt');
sub svc { my $p=shift; return $services{$p} // getservbyport($p,'tcp') // 'unknown'; }
my @out;
sub emit { my $line=shift; push @out,$line; print "$line\n"; }
my $interrupted=0;
$SIG{INT}=sub {$interrupted=1};
for my $host (@ARGV) {
 last if $interrupted;
 die "Invalid target: $host\n" if $host =~ /[\s\x00-\x1f]/ || length($host)>253 || $host =~ /\A-/;
 my ($ge,@addresses)=getaddrinfo($host,undef,{socktype=>SOCK_STREAM});
 if ($ge || !@addresses) { emit("Cannot resolve $host: $ge"); next; }
 my ($base,$numeric);
 for my $a (@addresses) {
   my $s; next unless socket($s,$a->{family},SOCK_STREAM,0);
   close $s;
   $base=$a;
   my ($ne,$num)=getnameinfo($a->{addr},NI_NUMERICHOST);
   $numeric=$ne?$host:$num;
   last;
 }
 if (!$base) { emit("Cannot create socket for $host"); next; }
 emit("Cat's Nmap $version | Target: $host ($numeric) | TCP connect");
 emit('PORT        STATE       SERVICE');
 my (@queue,%pending,%results);
 @queue=@ports;
 my $sel=IO::Select->new;
 my $start=time;
 while ((@queue || $sel->count) && !$interrupted) {
   while (@queue && $sel->count<$workers) {
     my $p=shift @queue;
     my $s;
     if (!socket($s,$base->{family},SOCK_STREAM,0)) { $results{$p}='error'; next; }
     my $flags=fcntl($s,F_GETFL,0);
     if (!defined $flags || !fcntl($s,F_SETFL,$flags|O_NONBLOCK)) { close $s; $results{$p}='error'; next; }
     my ($e,@dest)=getaddrinfo($numeric,"$p",{family=>$base->{family},socktype=>SOCK_STREAM});
     if ($e || !@dest) { close $s; $results{$p}='error'; next; }
     my $ok=connect($s,$dest[0]{addr});
     if ($ok) { $results{$p}='open'; close $s; next; }
     my $err=0+$!;
     if ($!{EINPROGRESS} || $!{EWOULDBLOCK} || $!{EALREADY}) {
       $sel->add($s);
       $pending{fileno($s)}={socket=>$s,port=>$p,deadline=>time+$timeout};
     } else {
       $results{$p}=($err==ECONNREFUSED)?'closed':(($err==EHOSTUNREACH || $err==ENETUNREACH)?'error':'filtered');
       close $s;
     }
   }
   my $now=time;
   my $wait=0.05;
   for my $item (values %pending) { my $left=$item->{deadline}-$now; $wait=$left if $left<$wait; }
   $wait=0 if $wait<0;
   for my $s ($sel->can_write($wait)) {
     my $id=fileno($s);
     my $item=delete $pending{$id} or next;
     $sel->remove($s);
     my $packed=getsockopt($s,SOL_SOCKET,SO_ERROR);
     my $err=defined($packed)?unpack('i',$packed):-1;
     $results{$item->{port}}=$err==0?'open':$err==ECONNREFUSED?'closed':'filtered';
     close $s;
   }
   $now=time;
   for my $id (keys %pending) {
     my $item=$pending{$id}; next if $item->{deadline}>$now;
     delete $pending{$id}; $sel->remove($item->{socket}); close $item->{socket};
     $results{$item->{port}}='filtered';
   }
 }
 for my $item (values %pending) { close $item->{socket}; }
 my %count=(open=>0,closed=>0,filtered=>0,error=>0);
 for my $p (sort {$a<=>$b} keys %results) {
   my $state=$results{$p}; $count{$state}++;
   next if !$verbose && $state ne 'open';
   my $name=svc($p);
   my $banner='';
   if ($banners && $state eq 'open') {
     eval {
       require IO::Socket::INET;
       local $SIG{ALRM}=sub {die "timeout\n"};
       alarm 2;
       my $sock=IO::Socket::INET->new(PeerAddr=>$numeric,PeerPort=>$p,Proto=>'tcp',Timeout=>1);
       if ($sock) {
         if ($p==80 || $p==8080 || $p==8000) { print {$sock} "HEAD / HTTP/1.0\r\nHost: $host\r\n\r\n"; }
         my $line=<$sock>;
         if (defined $line) { $line =~ s/[\x00-\x1f\x7f]/ /g; $banner=substr($line,0,70); }
         close $sock;
       }
       alarm 0;
     };
     alarm 0;
   }
   emit(sprintf('%-11s %-11s %s%s',"$p/tcp",$state,$name,$banner ne ''?" [$banner]":''));
 }
 emit(sprintf('Open: %d | Closed: %d | Filtered: %d | Error: %d | Scanned: %d/%d | Elapsed: %.2fs',@count{qw(open closed filtered error)},scalar(keys %results),scalar(@ports),time-$start));
}
if ($report ne '') {
 open my $fh,'>',$report or die "Cannot write $report: $!\n";
 print {$fh} join("\n",@out),"\n";
 close $fh or die "Cannot close report: $!\n";
 print "Report saved: $report\n";
}
exit($interrupted?130:0);
