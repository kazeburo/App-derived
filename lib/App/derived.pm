package App::derived;

use strict;
use warnings;
use 5.008005;
use File::Temp qw/tempfile/;
use File::Copy;
use IO::Socket::INET;
use POSIX qw(EINTR EAGAIN EWOULDBLOCK);
use Socket qw(IPPROTO_TCP TCP_NODELAY);
use Proclet;
use JSON ();
use Log::Minimal;

our $VERSION = '0.03';

my $_JSON = JSON->new()
    ->utf8(1)
    ->shrink(1)
    ->space_before(0)
    ->space_after(0)
    ->indent(0);

our $MAX_REQUEST_SIZE = 131072;
our $CRLF      = "\x0d\x0a";
our $DELIMITER = "\x20";

sub new {
    my $class = shift;
    my %opt = ref $_[0] ? %{$_[0]} : @_;
    my %args = (
        proclet  => Proclet->new,
        interval => 10,
        host     => 0,
        port     => 12306,
        timeout  => 10,
        services => {},
        %opt
    );
    bless \%args, $class;
}

sub add_service {
    my $self = shift;
    my ($key, $cmd) = @_;
    my ($tmpfh,$tmpfile) = tempfile(UNLINK=>0, EXLOCK=>0);
    print $tmpfh $_JSON->encode({
        status=>"INIT",
        persec => '0E0',
    });
    close $tmpfh;
    $self->{services}->{$key} = {
        cmd => ['/bin/bash', '-c', $cmd],
        file => $tmpfile,
        prev => undef,
    };
    debugf("add service: %s", $key);
    $self->{proclet}->service(
        code => sub {
            $0 = "$0 worker $key";
            $self->worker($key);
            exit;
        },
        tag => $key.'_worker',
    );
}

sub run {
    my $self = shift;

    my $localaddr = $self->{host} .':'. $self->{port};
    my $sock = IO::Socket::INET->new(
        Listen    => SOMAXCONN,
        LocalAddr => $localaddr,
        Proto     => 'tcp',
        (($^O eq 'MSWin32') ? () : (ReuseAddr => 1)),
    ) or die "failed to listen to port $localaddr: $!";


    $self->{proclet}->service(
        code => sub {
            $0 = "$0 server";
            $self->server($sock);
        },
        tag => 'server',
        worker => 3,
    );
    debugf("run proclet");
    $self->{proclet}->run;
}

sub DESTROY {
    my $self = shift;
    for my $key ( keys %{$self->{services}} ) {
        unlink $self->{services}->{$key}->{file};
    }
}

sub worker {
    my ($self, $service_key) = @_;
    my $service = $self->{services}->{$service_key};
    my $n = time;
    $n = $n - ( $n % $self->{interval}) + $self->{interval}; #next
    my $stop = 1;
    local $SIG{TERM} = sub { $stop = 0 };

    while ( $stop ) {
        while ( $stop ) {
            last if time >= $n;
            select undef, undef, undef, 0.1 ## no critic;
        }
        $n = $n + $self->{interval};
        local $Log::Minimal::AUTODUMP = 1;
        debugf("exec command for %s => %s", $service_key, $service);
        my ($result, $exit_code) = cap_cmd($service->{cmd});
        debugf("command [%s]: exit_code:%s result:%s", $service_key, $exit_code, $result);
        if ( ! defined $result ) {
            atomic_write($service->{file}, {
                status => "ERROR",
                persec => undef,
                raw => undef,
                exit_code => $exit_code,
                last_update => time,
            });
            next;
        }
    
        my $orig = $result;
        $result =~ s!^[^0-9]+!!;
        {
            no warnings;
            $result = int($result);
        }
        if ( ! defined $service->{prev} ) {
            $service->{prev} = $result;
            next;
        }
        my $derive = ($result - $service->{prev}) / $self->{interval};
        atomic_write( $service->{file}, {
            status => "OK",
            persec => $derive,
            raw => $orig,
            exit_code => $exit_code,
            last_update => time,
        });
        $service->{prev} = $result;
    }
}

sub cap_cmd {
    my ($cmdref) = @_;
    pipe my $logrh, my $logwh
        or die "Died: failed to create pipe:$!";
    my $pid = fork;
    if ( ! defined $pid ) {
        die "Died: fork failed: $!";
    } 

    elsif ( $pid == 0 ) {
        #child
        close $logrh;
        open STDOUT, '>&', $logwh
            or die "Died: failed to redirect STDOUT";
        close $logwh;
        exec @$cmdref;
        die "Died: exec failed: $!";
    }
    close $logwh;
    my $result;
    while(<$logrh>){
        chomp;chomp;
        $result .= $_;
    }
    close $logrh;
    while (wait == -1) {}
    my $exit_code = $?;
    $exit_code = $exit_code >> 8;
    if ( $exit_code != 0 ) {
        warnf("Error: command exited with code: $exit_code");
    }
    return ($result, $exit_code);
}

sub atomic_write {
    my ($writefile, $body) = @_;
    my ($tmpfh,$tmpfile) = tempfile(UNLINK=>0);
    print $tmpfh $_JSON->encode($body);
    close($tmpfh);
    move( $tmpfile, $writefile);
}

sub server {
    my $self = shift;
    my $sock = shift;

    while(1) {
        local $SIG{PIPE} = 'IGNORE';
        if ( my $conn = $sock->accept ) {
            debugf("[server] new connection from %s:%s", $conn->peerhost, $conn->peerport);
            $conn->blocking(0)
                or die "failed to set socket to nonblocking mode:$!";
            $conn->setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
                or die "setsockopt(TCP_NODELAY) failed:$!";            
            $self->handle_connection($conn);
            debugf("[server] close connection: %s:%s", $conn->peerhost, $conn->peerport);
            $conn->close;
        }
    }

}

sub handle_connection {
    my ($self, $conn) = @_;
    
    my $buf = '';
    my $req = +{};

    while (1) {
        my $rlen = read_timeout(
            $conn, \$buf, $MAX_REQUEST_SIZE - length($buf), length($buf), $self->{timeout},
        ) or last;
        if ( parse_read_buffer($buf, $req ) ) {
            $buf = '';
            if ( $req->{cmd} eq 'get' ) {
                my @keys = split /\x20+/, $req->{keys};
                my $result;
                debugf("[server] request get => %s from %s:%s", $req->{keys}, $conn->peerhost, $conn->peerport);
                for my $key ( @keys ) {
                    my $full;
                    if ( $key =~ m!:full$! ) {
                        $full = 1;
                        $key =~ s!:full$!!;
                    }
                    if ( exists $self->{services}->{$key} ) {
                        my $service = $self->{services}->{$key};
                        open my $fh, '<', $service->{file} or next;
                        my $val = do { local $/; <$fh> };
                        if ( $full ) {
                            $result .= join $DELIMITER, "VALUE", $key, 0, length($val);
                            $result .= $CRLF . $val . $CRLF;
                        }
                        else {
                            my $ref = $_JSON->decode($val);
                            if ( defined $ref->{persec} ) {
                                my $val = $ref->{persec};
                                $result .= join $DELIMITER, "VALUE", $key, 0, length($val);
                                $result .= $CRLF . $val . $CRLF;
                            }
                        }
                    }
                }
                $result .= "END" . $CRLF;
                write_all( $conn, $result, $self->{timeout} );
            }
            elsif ( $req->{cmd} eq 'version' ) {
                write_all( $conn, "VERSION $App::derived::VERSION$CRLF", $self->{timeout} );
            }
            elsif ( $req->{cmd} eq 'quit' ) {
                #do nothing
                last;
            }
            else {
                write_all( $conn, "ERROR".$CRLF, $self->{timeout} );
            }
        }
    }
    return;
}

sub parse_read_buffer {
    my ($buf, $ret) = @_;
    if ( $buf =~ /$CRLF$/o ) {
        my ($req_line) = split /$CRLF/, $buf;
        ($ret->{cmd}, $ret->{keys}) = split /$DELIMITER/o, $req_line, 2;
        $ret->{keys} ||= '';
        return 1;
    }
    return;
}

# returns (positive) number of bytes read, or undef if the socket is to be closed
sub read_timeout {
    my ($sock, $buf, $len, $off, $timeout) = @_;
    do_io(undef, $sock, $buf, $len, $off, $timeout);
}

# returns (positive) number of bytes written, or undef if the socket is to be closed
sub write_timeout {
    my ($sock, $buf, $len, $off, $timeout) = @_;
    do_io(1, $sock, $buf, $len, $off, $timeout);
}

# writes all data in buf and returns number of bytes written or undef if failed
sub write_all {
    my ($sock, $buf, $timeout) = @_;
    my $off = 0;
    while (my $len = length($buf) - $off) {
        my $ret = write_timeout($sock, $buf, $len, $off, $timeout)
            or return;
        $off += $ret;
    }
    return length $buf;
}

# returns value returned by $cb, or undef on timeout or network error
sub do_io {
    my ($is_write, $sock, $buf, $len, $off, $timeout) = @_;
    my $ret;
 DO_READWRITE:
    # try to do the IO
    if ($is_write) {
        $ret = syswrite $sock, $buf, $len, $off
            and return $ret;
    } else {
        $ret = sysread $sock, $$buf, $len, $off
            and return $ret;
    }
    unless ((! defined($ret)
                 && ($! == EINTR || $! == EAGAIN || $! == EWOULDBLOCK))) {
        return;
    }
    # wait for data
 DO_SELECT:
    while (1) {
        my ($rfd, $wfd);
        my $efd = '';
        vec($efd, fileno($sock), 1) = 1;
        if ($is_write) {
            ($rfd, $wfd) = ('', $efd);
        } else {
            ($rfd, $wfd) = ($efd, '');
        }
        my $start_at = time;
        my $nfound = select($rfd, $wfd, $efd, $timeout);
        $timeout -= (time - $start_at);
        last if $nfound;
        return if $timeout <= 0;
    }
    goto DO_READWRITE;
}

1;
__END__

=encoding utf8

=head1 NAME

App::derived - run command periodically and calculate rate and check from network

=head1 SYNOPSIS

  $ cat CmdsFile
  slowqueries: mysql -NB -e 'show global status like "Slow_queries%"'
  $ derived -p port CmdsFile

  $ telnet localhost port
  get slowqueris
  VALUE slowqueris 0 3
  0.2  # slow queries/sec

=head1 DESCRIPTION

derived runs commands periodically and capture integer value. And calculate per-second rate. 
You can retrieve these values from integrated memcached-protocol server

You can monitoring the variation of metrics through this daemon.

See detail for perldoc "derived"

=head1 AUTHOR

Masahiro Nagano E<lt>kazeburo@gmail.comE<gt>

=head1 SEE ALSO

<derived>

=head1 LICENSE

Copyright (C) Masahiro Nagano

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=cut
