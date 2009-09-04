use strict;
use warnings;
use Benchmark ':all';

use LWP::Simple;
use Cache::Memcached::Fast;

use WWW::Curl::Easy;
use WWW::Curl::Share;

my $mc = Cache::Memcached::Fast->new({ servers => [ 'localhost:12345' ] });

my $curl   = WWW::Curl::Easy->new;
$curl->setopt(CURLOPT_URL, 'http://localhost:8082/yappo');

cmpthese(2000, {
    memcached => sub {
        die unless ($mc->get('/yappo') eq 'yappo');
    },
    curl      => sub {
        open my $content_fh, '>', \my $content;
        $curl->setopt( CURLOPT_WRITEDATA, $content_fh);
        $curl->perform;
        die unless ($content eq 'yappo');
    },
    http      => sub {
        die unless (get 'http://localhost:8082/yappo') eq 'yappo';
    },
});

