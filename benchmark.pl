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
$curl->setopt(CURLOPT_URL, 'http://localhost:8082/yappo');

cmpthese(10000, {
    memcached        => sub {
        die unless ($mc->get('/yappo') eq 'yappo');
    },
    'memcached-fast' => sub {
        die unless ($mcf->get('/yappo') eq 'yappo');
    },
    curl             => sub {
        open my $content_fh, '>', \my $content;
        $curl->setopt( CURLOPT_WRITEDATA, $content_fh);
        $curl->perform;
        die unless ($content eq 'yappo');
    },
    'lwp-simple'     => sub {
        die unless (get 'http://localhost:8082/yappo') eq 'yappo';
    },
});


__END__
                  Rate    lwp-simple     memcached           curl memcached-fast
lwp-simple      2703/s            --          -39%           -75%           -86%
memcached       4464/s           65%            --           -58%           -77%
curl           10638/s          294%          138%             --           -45%
memcached-fast 19231/s          612%          331%            81%             --
