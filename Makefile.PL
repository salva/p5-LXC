use 5.014000;
use ExtUtils::MakeMaker;

WriteMakefile( NAME              => 'LXC',
               VERSION_FROM      => 'lib/LXC.pm',
               PREREQ_PM         => {},
               ABSTRACT_FROM     => 'lib/LXC.pm',
               AUTHOR            => 'Salvador Fandiño <sfandino@yahoo.com>',
               LICENSE           => 'GNU',
               LIBS              => ['-llxc'],
               DEFINE            => '',
               INC               => '-I.',
               OBJECT            => '$(O_FILES)',
             );
