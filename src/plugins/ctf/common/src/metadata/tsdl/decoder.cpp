/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2016-2017 Philippe Proulx <pproulx@efficios.com>
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "common/assert.h"
#include "common/uuid.h"
#include "compat/memstream.h"
#include "cpp-common/vendor/fmt/format.h"

#include "ast.hpp"
#include "decoder-packetized-file-stream-to-buf.hpp"
#include "decoder.hpp"
#include "parser-wrap.hpp"
#include "scanner.hpp"

#define TSDL_MAGIC 0x75d11d57

struct ctf_metadata_decoder
{
    explicit ctf_metadata_decoder(const bt2c::Logger& parentLogger) :
        logger {parentLogger, "PLUGIN/CTF/META/DECODER"}, config {logger}
    {
    }

    bt2c::Logger logger;
    struct ctf_scanner *scanner = nullptr;
    GString *text = nullptr;
    ctf_visitor_generate_ir::UP visitor;
    bt_uuid_t uuid {};
    bool is_uuid_set = false;
    int bo = 0;
    struct ctf_metadata_decoder_config config;
    bool has_checked_plaintext_signature = false;
};

struct packet_header
{
    uint32_t magic;
    bt_uuid_t uuid;
    uint32_t checksum;
    uint32_t content_size;
    uint32_t packet_size;
    uint8_t compression_scheme;
    uint8_t encryption_scheme;
    uint8_t checksum_scheme;
    uint8_t major;
    uint8_t minor;
} __attribute__((__packed__));

int ctf_metadata_decoder_is_packetized(FILE *fp, bool *is_packetized, int *byte_order,
                                       const bt2c::Logger& logger)
{
    uint32_t magic;
    size_t len;
    int ret = 0;

    *is_packetized = false;
    len = fread(&magic, sizeof(magic), 1, fp);
    if (len != 1) {
        BT_CPPLOGI_SPEC(
            logger,
            "Cannot read first metadata packet header: assuming the stream is not packetized.");
        ret = -1;
        goto end;
    }

    if (byte_order) {
        if (magic == TSDL_MAGIC) {
            *is_packetized = true;
            *byte_order = BYTE_ORDER;
        } else if (magic == GUINT32_SWAP_LE_BE(TSDL_MAGIC)) {
            *is_packetized = true;
            *byte_order = BYTE_ORDER == BIG_ENDIAN ? LITTLE_ENDIAN : BIG_ENDIAN;
        }
    }

end:
    rewind(fp);

    return ret;
}

ctf_metadata_decoder_up
ctf_metadata_decoder_create(const struct ctf_metadata_decoder_config *config)
{
    BT_ASSERT(config);
    BT_CPPLOGD_SPEC(config->logger, "Creating CTF metadata decoder");

    ctf_metadata_decoder *mdec = new ctf_metadata_decoder {config->logger};
    mdec->scanner = ctf_scanner_alloc(mdec->logger);
    if (!mdec->scanner) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(mdec->logger,
                                     "Cannot allocate a metadata lexical scanner: "
                                     "mdec-addr={}",
                                     fmt::ptr(mdec));
        goto error;
    }

    mdec->text = g_string_new(NULL);
    if (!mdec->text) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(mdec->logger,
                                     "Failed to allocate one GString: "
                                     "mdec-addr={}",
                                     fmt::ptr(mdec));
        goto error;
    }

    mdec->bo = -1;
    mdec->config = *config;
    mdec->visitor = ctf_visitor_generate_ir_create(config->self_comp, config->logger);
    if (!mdec->visitor) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(mdec->logger,
                                     "Failed to create a CTF IR metadata AST visitor: "
                                     "mdec-addr={}",
                                     fmt::ptr(mdec));
        goto error;
    }

    BT_CPPLOGD_SPEC(mdec->logger, "Created CTF metadata decoder: addr={}", fmt::ptr(mdec));
    goto end;

error:
    ctf_metadata_decoder_destroy(mdec);
    mdec = NULL;

end:
    return ctf_metadata_decoder_up {mdec};
}

void ctf_metadata_decoder_destroy(struct ctf_metadata_decoder *mdec)
{
    if (!mdec) {
        return;
    }

    if (mdec->scanner) {
        ctf_scanner_free(mdec->scanner);
    }

    if (mdec->text) {
        g_string_free(mdec->text, TRUE);
    }

    BT_CPPLOGD_SPEC(mdec->logger, "Destroying CTF metadata decoder: addr={}", fmt::ptr(mdec));

    delete mdec;
}

void ctf_metadata_decoder_deleter::operator()(ctf_metadata_decoder *decoder)
{
    ctf_metadata_decoder_destroy(decoder);
}

enum ctf_metadata_decoder_status
ctf_metadata_decoder_append_content(struct ctf_metadata_decoder *mdec, FILE *fp)
{
    enum ctf_metadata_decoder_status status = CTF_METADATA_DECODER_STATUS_OK;
    int ret;
    char *buf = NULL;
    bool close_fp = false;
    long start_pos = -1;
    bool is_packetized;

    BT_ASSERT(mdec);
    ret = ctf_metadata_decoder_is_packetized(fp, &is_packetized, &mdec->bo, mdec->logger);
    if (ret) {
        status = CTF_METADATA_DECODER_STATUS_ERROR;
        goto end;
    }

    if (is_packetized) {
        BT_CPPLOGI_SPEC(mdec->logger, "Metadata stream is packetized: mdec-addr={}",
                        fmt::ptr(mdec));
        ret = ctf_metadata_decoder_packetized_file_stream_to_buf(
            fp, &buf, mdec->bo, &mdec->is_uuid_set, mdec->uuid, mdec->logger);
        if (ret) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(
                mdec->logger,
                "Cannot decode packetized metadata packets to metadata text: "
                "mdec-addr={}, ret={}",
                fmt::ptr(mdec), ret);
            status = CTF_METADATA_DECODER_STATUS_ERROR;
            goto end;
        }

        if (strlen(buf) == 0) {
            /* An empty metadata packet is OK. */
            goto end;
        }

        /* Convert the real file pointer to a memory file pointer */
        fp = bt_fmemopen(buf, strlen(buf), "rb");
        close_fp = true;
        if (!fp) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(mdec->logger,
                                         "Cannot memory-open metadata buffer: {}: "
                                         "mdec-addr={}",
                                         strerror(errno), fmt::ptr(mdec));
            status = CTF_METADATA_DECODER_STATUS_ERROR;
            goto end;
        }
    } else if (!mdec->has_checked_plaintext_signature) {
        unsigned int major, minor;
        ssize_t nr_items;
        const long init_pos = ftell(fp);

        BT_CPPLOGI_SPEC(mdec->logger, "Metadata stream is plain text: mdec-addr={}",
                        fmt::ptr(mdec));

        if (init_pos < 0) {
            BT_CPPLOGE_ERRNO_APPEND_CAUSE_SPEC(mdec->logger, "Failed to get current file position",
                                               ".");
            status = CTF_METADATA_DECODER_STATUS_ERROR;
            goto end;
        }

        /* Check text-only metadata header and version */
        nr_items = fscanf(fp, "/* CTF %10u.%10u", &major, &minor);
        if (nr_items < 2) {
            BT_CPPLOGW_SPEC(
                mdec->logger,
                "Missing \"/* CTF major.minor\" signature in plain text metadata file stream: "
                "mdec-addr={}",
                fmt::ptr(mdec));
        }

        BT_CPPLOGI_SPEC(mdec->logger, "Found metadata stream version in signature: version={}.{}",
                        major, minor);

        if (!ctf_metadata_decoder_is_packet_version_valid(major, minor)) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(mdec->logger,
                                         "Invalid metadata version found in plain text signature: "
                                         "version={}.{}, mdec-addr={}",
                                         major, minor, fmt::ptr(mdec));
            status = CTF_METADATA_DECODER_STATUS_INVAL_VERSION;
            goto end;
        }

        if (fseek(fp, init_pos, SEEK_SET)) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(
                mdec->logger,
                "Cannot seek metadata file stream to initial position: {}: "
                "mdec-addr={}",
                strerror(errno), fmt::ptr(mdec));
            status = CTF_METADATA_DECODER_STATUS_ERROR;
            goto end;
        }

        mdec->has_checked_plaintext_signature = true;
    }

#if YYDEBUG
    if (mdec->logger.wouldLogT()) {
        yydebug = 1;
    }
#endif

    /* Save the file's position: we'll seek back to append the plain text */
    BT_ASSERT(fp);

    if (mdec->config.keep_plain_text) {
        start_pos = ftell(fp);
    }

    /* Append the metadata text content */
    ret = ctf_scanner_append_ast(mdec->scanner, fp);
    if (ret) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(mdec->logger,
                                     "Cannot create the metadata AST out of the metadata text: "
                                     "mdec-addr={}",
                                     fmt::ptr(mdec));
        status = CTF_METADATA_DECODER_STATUS_INCOMPLETE;
        goto end;
    }

    /* We know it's complete: append plain text */
    if (mdec->config.keep_plain_text) {
        BT_ASSERT(start_pos != -1);
        ret = fseek(fp, start_pos, SEEK_SET);
        if (ret) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(mdec->logger, "Failed to seek file: ret={}, mdec-addr={}",
                                         ret, fmt::ptr(mdec));
            status = CTF_METADATA_DECODER_STATUS_ERROR;
            goto end;
        }

        ret = bt_common_append_file_content_to_g_string(mdec->text, fp);
        if (ret) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(mdec->logger,
                                         "Failed to append to current plain text: "
                                         "ret={}, mdec-addr={}",
                                         ret, fmt::ptr(mdec));
            status = CTF_METADATA_DECODER_STATUS_ERROR;
            goto end;
        }
    }

    ret = ctf_visitor_semantic_check(0, &mdec->scanner->ast->root, mdec->logger);
    if (ret) {
        BT_CPPLOGE_APPEND_CAUSE_SPEC(mdec->logger,
                                     "Validation of the metadata semantics failed: "
                                     "mdec-addr={}",
                                     fmt::ptr(mdec));
        status = CTF_METADATA_DECODER_STATUS_ERROR;
        goto end;
    }

    if (mdec->config.create_trace_class) {
        ret = ctf_visitor_generate_ir_visit_node(mdec->visitor.get(), &mdec->scanner->ast->root);
        switch (ret) {
        case 0:
            /* Success */
            break;
        case -EINCOMPLETE:
            BT_CPPLOGD_SPEC(mdec->logger,
                            "While visiting metadata AST: incomplete data: "
                            "mdec-addr={}",
                            fmt::ptr(mdec));
            status = CTF_METADATA_DECODER_STATUS_INCOMPLETE;
            goto end;
        default:
            BT_CPPLOGE_APPEND_CAUSE_SPEC(mdec->logger,
                                         "Failed to visit AST node to create CTF IR objects: "
                                         "mdec-addr={}, ret={}",
                                         fmt::ptr(mdec), ret);
            status = CTF_METADATA_DECODER_STATUS_IR_VISITOR_ERROR;
            goto end;
        }
    }

end:
#if YYDEBUG
    yydebug = 0;
#endif

    if (fp && close_fp) {
        if (fclose(fp)) {
            BT_CPPLOGE_SPEC(mdec->logger,
                            "Cannot close metadata file stream: "
                            "mdec-addr={}",
                            fmt::ptr(mdec));
        }
    }

    free(buf);

    return status;
}

bt2::TraceClass::Shared ctf_metadata_decoder_get_ir_trace_class(struct ctf_metadata_decoder *mdec)
{
    BT_ASSERT_DBG(mdec);
    BT_ASSERT_DBG(mdec->config.create_trace_class);
    return ctf_visitor_generate_ir_get_ir_trace_class(mdec->visitor.get());
}

struct ctf_trace_class *
ctf_metadata_decoder_borrow_ctf_trace_class(struct ctf_metadata_decoder *mdec)
{
    BT_ASSERT_DBG(mdec);
    BT_ASSERT_DBG(mdec->config.create_trace_class);
    return ctf_visitor_generate_ir_borrow_ctf_trace_class(mdec->visitor.get());
}

const char *ctf_metadata_decoder_get_text(struct ctf_metadata_decoder *mdec)
{
    BT_ASSERT_DBG(mdec);
    BT_ASSERT_DBG(mdec->config.keep_plain_text);
    return mdec->text->str;
}

static enum ctf_metadata_decoder_status find_uuid_in_trace_decl(struct ctf_metadata_decoder *mdec,
                                                                struct ctf_node *trace_node,
                                                                bt_uuid_t uuid)
{
    enum ctf_metadata_decoder_status status = CTF_METADATA_DECODER_STATUS_OK;
    struct ctf_node *entry_node;
    struct bt_list_head *decl_list = &trace_node->u.trace.declaration_list;
    char *left = NULL;

    bt_list_for_each_entry (entry_node, decl_list, siblings) {
        if (entry_node->type == NODE_CTF_EXPRESSION) {
            int ret;

            left = ctf_ast_concatenate_unary_strings(&entry_node->u.ctf_expression.left);
            if (!left) {
                BT_CPPLOGE_APPEND_CAUSE_SPEC(mdec->logger, "Cannot concatenate unary strings.");
                status = CTF_METADATA_DECODER_STATUS_ERROR;
                goto end;
            }

            if (strcmp(left, "uuid") == 0) {
                ret =
                    ctf_ast_get_unary_uuid(&entry_node->u.ctf_expression.right, uuid, mdec->logger);
                if (ret) {
                    BT_CPPLOGE_APPEND_CAUSE_SPEC(mdec->logger, "Invalid trace's `uuid` attribute.");
                    status = CTF_METADATA_DECODER_STATUS_ERROR;
                    goto end;
                }

                goto end;
            }

            g_free(left);
            left = NULL;
        }
    }

    status = CTF_METADATA_DECODER_STATUS_NONE;

end:
    g_free(left);
    return status;
}

enum ctf_metadata_decoder_status
ctf_metadata_decoder_get_trace_class_uuid(struct ctf_metadata_decoder *mdec, bt_uuid_t uuid)
{
    enum ctf_metadata_decoder_status status = CTF_METADATA_DECODER_STATUS_INCOMPLETE;
    struct ctf_node *root_node = &mdec->scanner->ast->root;
    struct ctf_node *trace_node;

    if (!root_node) {
        status = CTF_METADATA_DECODER_STATUS_INCOMPLETE;
        goto end;
    }

    trace_node = bt_list_entry(root_node->u.root.trace.next, struct ctf_node, siblings);
    if (!trace_node) {
        status = CTF_METADATA_DECODER_STATUS_INCOMPLETE;
        goto end;
    }

    status = find_uuid_in_trace_decl(mdec, trace_node, uuid);

end:
    return status;
}
