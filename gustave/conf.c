#include "afl/common.h"

#include "qapi/qmp/qdict.h"
#include "qapi/qmp/qlist.h"
#include "qapi/qmp/qjson.h"
#include "qapi/qmp/qnum.h"
#include "qapi/qmp/qnull.h"
#include "qapi/qmp/qstring.h"
#include "qemu/option_int.h"
#include "qemu/config-file.h"
#include "migration/qemu-file.h"
#include "io/channel-file.h"

static QDict *parse_json(const char *filename)
{
    QIOChannel  *ioc;
    QEMUFile    *f;
    QObject     *obj;
    QDict       *dict;
    uint8_t     *data;
    struct stat st;

    if (stat(filename, &st) < 0) {
        fprintf(stderr, "stat(json) failed\n");
        return NULL;
    }

    ioc = QIO_CHANNEL(qio_channel_file_new_path(filename, O_RDONLY, 0, NULL));
    f   = qemu_file_new_input(ioc);

    if (!f) {
        fprintf(stderr, "qemu_file_new_input failed\n");
        return NULL;
    }

    object_unref(OBJECT(ioc));

    data = g_malloc(st.st_size);
    qemu_get_buffer(f, data, st.st_size);
    qemu_fclose(f);

    obj = qobject_from_json((const char*)data, NULL);
    if (!obj) {
        fprintf(stderr, "Could not parse JSON\n");
        return NULL;
    }

    dict = qobject_to(QDict, obj);
    if (!dict) {
        qobject_unref(obj);
        fprintf(stderr, "Invalid JSON object given\n");
        return NULL;
    }

    return dict;
}

#define afl_conf_obj(dict, key, type, cast)                     \
    ({                                                          \
        QObject *obj = qdict_get(dict, key);                    \
                                                                \
        if (obj == NULL) {                                      \
            fprintf(stderr, "afl conf qdict get failed\n");     \
            exit(EXIT_FAILURE);                                 \
        }                                                       \
                                                                \
        if (qobject_type(obj) != type) {                        \
            fprintf(stderr, "afl conf bad type for: \'"key"\'\n"); \
            exit(EXIT_FAILURE);                                 \
        }                                                       \
                                                                \
        qobject_to(cast, obj);                                  \
    })

static void afl_map_obj_conf(afl_t *afl, QDict *json)
{
    afl->config.qemu.timeout = qnum_get_int(
        afl_conf_obj(json,"user-timeout",QTYPE_QNUM,QNum));
    afl->config.qemu.mm_ranges = qstring_get_str(
        afl_conf_obj(json,"vm-mem-ranges",QTYPE_QSTRING,QString));
    afl->config.tgt.forkserver = qnum_get_uint(
        afl_conf_obj(json,"vm-forkserver",QTYPE_QNUM,QNum));
    afl->config.tgt.persistent = qnum_get_uint(
        afl_conf_obj(json,"vm-persistent",QTYPE_QNUM,QNum));
    afl->config.tgt.persistent_return = qnum_get_uint(
        afl_conf_obj(json,"vm-persistent-return",QTYPE_QNUM,QNum));
    afl->config.tgt.panic = qnum_get_uint(
        afl_conf_obj(json,"vm-panic",QTYPE_QNUM,QNum));
}

void afl_init_conf(afl_t *afl)
{
    const char *fname;
    QDict      *json;

    fname = qemu_opt_get(qemu_find_opts_singleton("gustave"), "gustave");
    if (!fname) {
        fprintf(stderr, "need GUSTAVE configuration file\n");
        exit(EXIT_FAILURE);
    }

    json = parse_json(fname);
    if (!json) {
        fprintf(stderr, "can't parse GUSTAVE json file\n");
        exit(EXIT_FAILURE);
    }

    afl_map_obj_conf(afl, json);

    /* XXX: should unref object, but copy retrieved strings first */
    /* qobject_unref(json); */
}
