package LXC::C;

use strict;
use warnings;

1;

__END__

=head1 NAME

LXC::C

=head1 DESCRIPTION

Low level wrapping for liblxc.

=head1 CONSTANTS

=head1 FUNCTIONS

=over 4

=item get_wait_states()

=item get_global_config_item(key)

=item get_version()

=item list_containers(path)

=item log_close()

=item __container_get_name(container)

=item __container_get_configfile(container)

=item __container_get_pidfile(self)

=item container_get_error_string(self)

=item container_get_error_num(self)

=item container_get_daemonize(self)

=item container_get_config_path_2(self)

=back

=cut
