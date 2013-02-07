use strict;
use warnings;
use Module::Build;

my $build = Module::Build->new(
    license              => 'perl',
    dynamic_config       => 0,

    build_requires       => {
        'Test::More' => '0.98',
        'Test::Requires' => 0,
    },
    configure_requires   => { 'Module::Build' => '0.38' },
    requires             => {
        perl => '5.008005',
        'Getopt::Long'                      => '0',
        'Pod::Usage'                        => '0',
        'File::Temp'                        => '0',
        'File::Copy'                        => '0',
        'IO::Socket::INET'                  => '0',
        'POSIX'                             => '0',
        'Proclet'                           => '0.21',
        'JSON'                              => '2.53',
        'Log::Minimal'                      => '0.14',
    },

    no_index    => { 'directory' => [ 'inc' ] },
    name        => 'App-derived',
    module_name => 'App::derived',

    script_files => ['bin/derived'],

    test_files => (-d '.git' || $ENV{RELEASE_TESTING}) ? 't/ xt/' : 't/',
    recursive_test_files => 1,
   
    create_readme  => 1,
    create_license => 1,
);
$build->create_build_script();
