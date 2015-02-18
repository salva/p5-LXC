#define PERL_NO_GET_CONTEXT
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#define MATH_INT64_NATIVE_IF_AVAILABLE 1
#include "perl_math_int64.h"

#include <lxc/lxccontainer.h>
#include <lxc/attach_options.h>
#include "methods.h"
#include "accessors.h"
#include "constants.h"

#define FREEME_VECTOR 1
#define FREEME_STRINGS 2
#define FREEME_OBJECTS 4
#define FREEME_ALL (FREEME_VECTOR|FREEME_STRINGS|FREEME_OBJECTS)

typedef char **freeme_charpp;
typedef char **charpp;

static SV *
SvRV_safe(pTHX_ SV *sv, int sv_type, char *klass, int required, char *arg_name) {
    if (SvOK(sv)) {
        if (SvROK(sv)) {
            if (!klass || (sv_derived_from(sv, klass))) {
                SV *sv = SvRV(sv);
                if (!sv_type || (SvTYPE(sv) == sv_type))
                    return sv;
                Perl_croak(aTHX_ "object of type %d expected for argument %s, %s found",
                           sv_type, arg_name, SvTYPE(sv));
            }
            Perl_croak(aTHX_ "object of class %s expected for argument %s, %s found",
                       klass, arg_name, sv_reftype(sv, 1));
        }
        Perl_croak(aTHX_ "object of class %s expected for argument %s, scalar found",
                   klass, arg_name);
    }
    if (required)
        Perl_croak(aTHX_ "object of class %s expected for argument %s, undef found", klass, arg_name);
    return NULL;
}

static void *
sv2obj(pTHX_ SV *sv, char *klass, int required, char *arg_name) {
    return SvRV_safe(aTHX_ sv, 0, klass, required, arg_name);
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

static charpp
sv2charpp(pTHX_ SV *sv, int required, char *arg_name) {
    AV *av = (AV*)SvRV_safe(aTHX_ sv, SVt_PVAV, NULL, required, arg_name);
    if (av) {
        SSize_t i, n;
        char **argp;
        n = av_len(av) + 1;
        Newx(argp, n + 1, char *);
        SAVEFREEPV(argp);
        for (i = 0; i < n; i++) {
            SV *sv, **svp;
            svp = av_fetch(av, i, 0);
            sv = sv_2mortal(newSVsv(svp ? *svp : &PL_sv_undef));
            argp[i] = SvPV_nolen(sv);
        }
        argp[n] = 0;
        return argp;
    }
    return NULL;
}

static SV *
charpp2sv(pTHX_ charpp argp, SSize_t n, int freeme) {
    SSize_t i;
    AV *av;
    if (n == -1) for (n = 0; argp && argp[n]; n++);
    av = (AV*)sv_2mortal((SV*)newAV());
    for (i = 0; i < n; i++) {
        char *arg = argp[i];
        av_push(av, (arg ? newSVpv(arg, 0) : &PL_sv_undef));
        if (arg && (freeme & FREEME_STRINGS)) free(argp[i]);
    }
    if (argp && (freeme & FREEME_VECTOR)) free(argp);
    return newRV_inc((SV*)av);
}

static SV *
objp2sv(pTHX_ void **objp, SSize_t n, char *klass, int freeme) {
    SSize_t i;
    AV *av;
    if (n == -1) for (n = 0; objp && objp[n]; n++);
    av = (AV*)sv_2mortal((SV*)newAV());
    for (i = 0; i < n; i++) {
        void *obj = objp[i];
        av_push(av, (obj ? obj2sv(aTHX_ obj, klass) : &PL_sv_undef));
    }
    if (objp && (freeme & FREEME_VECTOR)) free(objp);
    return newRV_inc((SV *)av);
}

static SV *
lxc_snapshot2sv(pTHX_ struct lxc_snapshot *ss) {
    HV *hv = (HV*)sv_2mortal((SV*)newHV());
    hv_stores(hv, "name", newSVpv(ss->name, 0));
    hv_stores(hv, "comment_pathname", newSVpv(ss->comment_pathname, 0));
    hv_stores(hv, "timestamp", newSVpv(ss->timestamp, 0));
    hv_stores(hv, "lxcpath", newSVpv(ss->lxcpath, 0));
    return sv_bless(newRV_inc((SV*)hv), gv_stashpv("LXC::Snapshot", GV_ADD));
}

static SV *
lxc_snapshotv2sv(pTHX_ struct lxc_snapshot *ssv, SSize_t n, int freeme) {
    SSize_t i;
    AV *av = (AV*)sv_2mortal((SV*)newAV());
    for (i = 0; i < n; i++) {
        struct lxc_snapshot *ss = ssv + i;
        av_push(av, lxc_snapshot2sv(aTHX_ ss));
        if (freeme & FREEME_OBJECTS)
            (ss->free)(ss);
    }
    if (freeme & FREEME_VECTOR)
        free(ssv);
    return newRV_inc((SV*)av);
}

static SV *
pid_t2sv(pTHX_ pid_t pid) {
    return ((sizeof(pid_t) > sizeof(IV))
            ? newSVi64(pid)
            : newSViv(pid));
}

static SV *
hv_fetchs_safe(pTHX_ HV *hv, char *pv) {
    SV **svp = hv_fetch(hv, pv, strlen(pv), 0);
    return (svp ? *svp : &PL_sv_undef);
}

static IV
hv_fetchs_iv(pTHX_ HV *hv, char *pv, IV def) {
    SV *sv = hv_fetchs_safe(aTHX_ hv, pv);
    return (SvOK(sv) ? SvIV(sv) : def);
}

static char *
hv_fetchs_pv(pTHX_ HV *hv, char *pv) {
    SV *sv = hv_fetchs_safe(aTHX_ hv, pv);
    return (SvOK(sv) ? SvPV_nolen(sv_mortalcopy(sv)) : NULL);
}

static lxc_attach_options_t *
sv2lxc_attach_options_t(pTHX_ SV *sv, int required, char *arg_name) {
    HV *hv = (HV*)SvRV_safe(aTHX_ sv, SVt_PVHV, NULL, required, arg_name);
    if (hv) {
        lxc_attach_options_t *ao;
        Newxz(ao, 1, lxc_attach_options_t);
        SAVEFREEPV(ao);
        ao->attach_flags = hv_fetchs_iv(aTHX_ hv, "attach_flags", LXC_ATTACH_DEFAULT);
        ao->namespaces   = hv_fetchs_iv(aTHX_ hv, "namespaces", -1);
        ao->personality  = hv_fetchs_iv(aTHX_ hv, "personality", -1);
        ao->initial_cwd  = hv_fetchs_pv(aTHX_ hv, "initial_cwd");
        ao->uid          = hv_fetchs_iv(aTHX_ hv, "uid", -1);
        ao->gid          = hv_fetchs_iv(aTHX_ hv, "gid", -1);
        ao->env_policy   = hv_fetchs_iv(aTHX_ hv, "env_policy", LXC_ATTACH_KEEP_ENV);
        /* FIXME: add support for extra_env_vars and extra_keep_env */
        ao->stdin_fd     = hv_fetchs_iv(aTHX_ hv, "stdin_fd", 0);
        ao->stdout_fd    = hv_fetchs_iv(aTHX_ hv, "stdout_fd", 1);
        ao->stderr_fd    = hv_fetchs_iv(aTHX_ hv, "stderr_fd", 2);
        return ao;
    }
    return NULL;
}

static void
call_cv(void *ptr) {
    return;
}

MODULE = LXC    PACKAGE = LXC::C   PREFIX = lxc_

BOOT:
    PERL_MATH_INT64_LOAD_OR_CROAK;

int
lxc_CLONE_KEEPNAME()

int
lxc_CLONE_KEEPMACADDR()

int
lxc_CLONE_SNAPSHOT()

int
lxc_CLONE_KEEPBDEVTYPE()

int
lxc_CLONE_MAYBE_SNAPSHOT()

int
lxc_CLONE_MAXFLAGS()

int
lxc_CREATE_QUIET()

int
lxc_CREATE_MAXFLAGS()

SV *
lxc_get_wait_states()
PREINIT:
    int n;
    char **states;
CODE:
    n = lxc_get_wait_states(NULL);
    Newx(states, n + 1, char *);
    SAVEFREEPV(states);
    if (lxc_get_wait_states((const char **)states) != n)
        Perl_croak(aTHX_ "internal error: unexpected number of states!!!");
    RETVAL = charpp2sv(aTHX_ states, n, 0);
OUTPUT:
    RETVAL

const char *
lxc_get_global_config_item(const char *key)

const char *
lxc_get_version()

void
lxc_list_containers(const char *lxcpath)
ALIAS:
    list_all_containers     = 0
    list_defined_containers = 1
    list_active_containers  = 2
PREINIT:
    int n;
    charpp names = 0;
    struct lxc_container **cret = 0;
    SV *names_sv, *cret_sv;
PPCODE:
    switch (ix) {
    case 0:
        n = list_all_containers(lxcpath, &names, &cret); break;
    case 1:
        n = list_defined_containers(lxcpath, &names, &cret); break;
    case 2:
        n = list_active_containers(lxcpath, &names, &cret); break;
    default:
        Perl_croak(aTHX_ "internal error: bad index %d", ix);
    }
    names_sv = sv_2mortal(charpp2sv(aTHX_ names, n, FREEME_VECTOR));
    cret_sv = sv_2mortal(objp2sv(aTHX_ (void **)cret, n, "LXC::Container", FREEME_VECTOR));
    EXTEND(SP, 2);
    PUSHs(names_sv);
    PUSHs(cret_sv);

void
lxc_log_close();

char *
lxc___container_get_name(self)
    struct lxc_container *self

char *
lxc___container_get_configfile(self)
    struct lxc_container *self

char *
lxc___container_get_pidfile(self)
    struct lxc_container *self

char *
lxc_container_get_error_string(self)
    struct lxc_container *self

int
lxc_container_get_error_num(self)
    struct lxc_container *self

bool
lxc_container_get_daemonize(self)
    struct lxc_container *self

char *
lxc_container_get_config_path_2(self)
    struct lxc_container *self

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
lxc_container_start(self, useinit, argv)
    struct lxc_container *self
    int useinit
    charpp argv

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

bool
lxc_container_create(self, t, bdevtype, specs, flags, argv)
    struct lxc_container *self
    const char *t
    const char *bdevtype
    struct bdev_specs *specs
    int flags
    charpp argv

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

char *
lxc_container_get_keys(self, key)
    struct lxc_container *self
    const char *key
PREINIT:
    int inlen = 0;
CODE:
    inlen = lxc_container_get_keys(self, key, NULL, 0);
    if (inlen >= 0) {
        Newx(RETVAL, inlen + 1, char);
        SAVEFREEPV(RETVAL);
        if (lxc_container_get_keys(self, key, RETVAL, inlen) != inlen)
            Perl_croak(aTHX_ "internal error: unexpected inlen change");
        RETVAL[inlen] = '\0';
    }
    else
        RETVAL = NULL;
OUTPUT:
    RETVAL

freeme_charpp
lxc_container_get_interfaces(self)
    struct lxc_container *self

freeme_charpp
lxc_container_get_ips(self, interface, family, scope)
    struct lxc_container *self
    const char *interface
    const char *family
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

struct lxc_container *
lxc_container_clone(self, newname, lxcpath, flags, bdevtype, bdevdata, newsize, hookargs)
    struct lxc_container *self
    const char *newname
    const char *lxcpath
    int flags
    const char *bdevtype
    const char *bdevdata
    uint64_t newsize
    charpp hookargs

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

SV *
lxc_container_attach(self, callback, options)
    struct lxc_container *self
    CV *callback
    lxc_attach_options_t *options
PREINIT:
    int r;
    pid_t pid;
CODE:
    r = lxc_container_attach(self, &call_cv, cv, options, &pid);
    if (r < 0)
        RETVAL = &PL_sv_undef;
    else
        RETVAL = pid_t2sv(aTHX_ pid);
OUTPUT:
    RETVAL


=for dev_null
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

SV *
lxc_container_snapshot_list(self)
    struct lxc_container *self
PREINIT:
    SSize_t n;
    struct lxc_snapshot *ssv;
CODE:
    n = lxc_container_snaphost_list(self, &ssv);
    RETVAL = lxc_snapshotv2sv(aTHX_ ssv, n, FREEME_ALL);
OUTPUT:
    RETVAL

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

struct lxc_container *
lxc_container_new(const char *name, const char *configpath);

int
lxc_container_get(struct lxc_container *c)

int
lxc_container_put(struct lxc_container *c)

