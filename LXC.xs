#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#define MATH_INT64_NATIVE_IF_AVAILABLE 1
#include "perl_math_int64.h"

#include <lxc/lxccontainer.h>
#include "methods.h"

typedef char **freeme_char_pp;
typedef char **char_pp;

static void *
sv2obj(pTHX_ SV *sv, char *klass, int required) {
    if (SvOK(sv)) {
        if (SvROK(sv)) {
            IV tmp = SvIV((SV*)SvRV(sv));
            if (sv_isa(sv, klass))
                return INT2PTR(void *, tmp);
            Perl_croak(aTHX_ "object of class %s expected, %s found",
                       klass, sv_refttype(sv, 1));
        }
        Perl_croak(aTHX_ "object of class %s expected", klass);
    }
    if (required)
        Perl_croak(aTHX_ "object of class %s expected, undef found", klass);
    return NULL;
}

static SV*
obj2sv(pTHX_ void *obj, char *klass) {
    if (obj) {
        SV *sv = newSV(0);
        sv_setref_pv(sv, klass, obj);
        return sv;
    }
    return &PL_sv_undef;
}

static char **
svs2argv(pTHX_ SV **svp, int n) {
    int i;
    char **argv;
    Newx(argv, n + 1, char *);
    SAVEFREEPV(argv);
    argv[n] = 0;
    for (i = 0; i < n; i++)
        argv[i] = SvPV_nolen(svp[i]);
    return argv;
}

MODULE = LXC    PACKAGE = LXC

BOOT:
    PERL_MATH_INT64_LOAD_OR_CROAK;

MODULE = LXC    PACKAGE = LXC::Container    PREFIX = lxc_container_

bool
lxc_container_is_defined(self)
    struct lxc_container *self

const char *
lxc_container_state(self)
    struct lxc_container *self

bool
lxc_container_is_running(self)
    struct lxc_container *self

bool
lxc_container_freeze(self)
    struct lxc_container *self

bool
lxc_container_unfreeze(self)
    struct lxc_container *self

pid_t
lxc_container_init_pid(self)
    struct lxc_container *self

bool
lxc_container_load_config(self, alt_file)
    struct lxc_container *self
    const char *alt_file

bool
lxc_container_start(self, useinit, ...)
    struct lxc_container *self
    int useinit
PREINIT:
    int i;
    char **argv;
CODE:
    RETVAL = lxc_container_start(self, useinit,
                                 svs2argv(aTHX_ &(ST(2)), items - 2));
OUTPUT:
    RETVAL

bool
lxc_container_stop(self)
    struct lxc_container *self

bool
lxc_container_want_daemonize(self, state)
    struct lxc_container *self
    bool state

bool
lxc_container_want_close_all_fds(self, state)
    struct lxc_container *self
    bool state

char *
lxc_container_config_file_name(self)
    struct lxc_container *self

bool
lxc_container_wait(self, state, timeout)
    struct lxc_container *self
    const char *state
    int timeout

bool
lxc_container_set_config_item(self, key, value)
    struct lxc_container *self
    const char *key
    const char *value

bool
lxc_container_destroy(self)
    struct lxc_container *self

bool
lxc_container_destroy_with_snapshots(self)
    struct lxc_container *self

bool
lxc_container_save_config(self, alt_file)
    struct lxc_container *self
    const char *alt_file

=for dev_null
bool
lxc_container_create(self, t, bdevtype, specs, flags, argv)
    struct lxc_container *self
    const char *t
    const char *bdevtype
    struct bdev_specs *specs
    int flags
    char const **argv
=cut

bool
lxc_container_rename(self, newname)
    struct lxc_container *self
    const char *newname

bool
lxc_container_reboot(self)
    struct lxc_container *self

bool
lxc_container_shutdown(self, timeout)
    struct lxc_container *self
    int timeout

void
lxc_container_clear_config(self)
    struct lxc_container *self

bool
lxc_container_clear_config_item(self, key)
    struct lxc_container *self
    const char *key

int
lxc_container_get_config_item(self, key, retv, inlen)
    struct lxc_container *self
    const char *key
    char *retv
    int inlen

char *
lxc_container_get_running_config_item(self, key)
    struct lxc_container *self
    const char *key

int
lxc_container_get_keys(self, key, retv, inlen)
    struct lxc_container *self
    const char *key
    char *retv
    int inlen

freeme_char_pp
lxc_container_get_interfaces(self)
    struct lxc_container *self

freeme_char_pp
lxc_container_get_ips(self, interface, family, scope)
    struct lxc_container *self
    const char * interface
    const char * family
    int scope

int
lxc_container_get_cgroup_item(self, subsys, retv, inlen)
    struct lxc_container *self
    const char *subsys
    char *retv
    int inlen

bool
lxc_container_set_cgroup_item(self, subsys, value)
    struct lxc_container *self
    const char *subsys
    const char *value

const char *
lxc_container_get_config_path(self)
    struct lxc_container *self

bool
lxc_container_set_config_path(self, path)
    struct lxc_container *self
    const char *path

=for dev_null
struct lxc_container *
lxc_container_clone(self, newname, lxcpath, flags, bdevtype, bdevdata, newsize, hookargs)
    struct lxc_container *self
    const char *newname
    const char *lxcpath
    int flags
    const char *bdevtype
    const char *bdevdata
    uint64_t newsize
    char **hookargs
=cut

=for dev_null
int
lxc_container_console_getfd(self, ttynum, masterfd)
   struct lxc_container *self
   int *ttynum
   int *masterfd
=cut

int
lxc_container_console(self, ttynum, stdinfd, stdoutfd, stderrfd, escape)
    struct lxc_container *self
    int ttynum
    int stdinfd
    int stdoutfd
    int stderrfd
    int escape

=for dev_null
int
lxc_container_attach(self, exec_function, exec_payload, options, attached_process)
    struct lxc_container *self
    lxc_attach_exec_t exec_function
    void *exec_payload
    lxc_attach_options_t *options
    pid_t *attached_process

int
lxc_container_attach_run_wait(self, options, program)
    struct lxc_container *self
    lxc_attach_options_t *options
    const char *program
=cut

int
lxc_container_snapshot(self, commentfile)
    struct lxc_container *self
    const char *commentfile

=for dev_null
int
lxc_container_snapshot_list(self, snapshots)
    struct lxc_container *self
    struct lxc_snapshot **snapshots
=cut

bool
lxc_container_snapshot_restore(self, snapname, newname)
    struct lxc_container *self
    const char *snapname
    const char *newname

bool
lxc_container_snapshot_destroy(self, snapname)
    struct lxc_container *self
    const char *snapname

bool
lxc_container_snapshot_destroy_all(self)
    struct lxc_container *self

bool
lxc_container_may_control(self)
    struct lxc_container *self

bool
lxc_container_add_device_node(self, src_path, dest_path)
    struct lxc_container *self
    const char *src_path
    const char *dest_path

bool
lxc_container_remove_device_node(self, src_path, dest_path)
    struct lxc_container *self
    const char *src_path
    const char *dest_path

bool
lxc_container_checkpoint(self, directory, stop, verbose)
    struct lxc_container *self
    char *directory
    bool stop
    bool verbose

bool
lxc_container_restore(self, directory, verbose)
    struct lxc_container *self
    char *directory
    bool verbose

void
lxc_snapshot_free(self)
    struct lxc_snapshot *self

struct lxc_container *
lxc_container_new(const char *name, const char *configpath);

