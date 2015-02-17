
static char *
lxc___container_get_name(struct lxc_container *c) {
    return c->name;
}

static char *
lxc___container_get_configfile(struct lxc_container *c) {
    return c->configfile;
}

static char *
lxc___container_get_pidfile(struct lxc_container *c) {
    return c->pidfile;
}

static char *
lxc_container_get_error_string(struct lxc_container *c) {
    return c->error_string;
}

static int
lxc_container_get_error_num(struct lxc_container *c) {
    return c->error_num;
}

static bool
lxc_container_get_daemonize(struct lxc_container *c) {
    return c->daemonize;
}

static char *
lxc_container_get_config_path_2(struct lxc_container *c) {
    return c->config_path;
}

static char *
lxc_snapshot_get_name(struct lxc_snapshot *s) {
    return s->name;
}

static char *
lxc_snapshot_get_comment_pathname(struct lxc_snapshot *s) {
    return s->comment_pathname;
}

static char *
lxc_snapshot_get_timestamp(struct lxc_snapshot *s) {
    return s->timestamp;
}

static char *
lxc_snapshot_get_lxcpath(struct lxc_snapshot *s) {
    return s->lxcpath;
}

