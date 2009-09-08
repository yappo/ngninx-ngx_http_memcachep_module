use strict;
use warnings;
use Benchmark ':all';

use LWP::Simple;
use Cache::Memcached;
use Cache::Memcached::Fast;

use WWW::Curl::Easy;
use WWW::Curl::Share;

my $mc  = Cache::Memcached->new({ servers => [ 'localhost:12345' ] });
my $mcf = Cache::Memcached::Fast->new({ servers => [ 'localhost:12345' ] });

my $curl   = WWW::Curl::Easy->new;
$curl->setopt(CURLOPT_URL, 'http://localhost:8082/bigfiles/1M/1.txt');

# get /bigfiles/1M/1.txt
my $size = 1024*1024;
cmpthese(2000, {
    memcached        => sub {
        warn 'memcached' unless length($mc->get('/bigfiles/1M/1.txt')) == $size;
    },
    'memcached-fast' => sub {
        warn 'memcached-fast' unless length($mcf->get('/bigfiles/1M/1.txt')) == $size;
    },
    curl             => sub {
        open my $content_fh, '>', \my $content;
        $curl->setopt( CURLOPT_WRITEDATA, $content_fh);
        $curl->perform;
        die 'curl' unless length($content) == $size;
    },
    'lwp-simple'     => sub {
        die 'lwp-simple' unless length(get 'http://localhost:8082/bigfiles/1M/1.txt') == $size;
    },
});


__END__
                  Rate    lwp-simple     memcached           curl memcached-fast
lwp-simple      2703/s            --          -39%           -75%           -86%
memcached       4464/s           65%            --           -58%           -77%
curl           10638/s          294%          138%             --           -45%
memcached-fast 19231/s          612%          331%            81%             --
