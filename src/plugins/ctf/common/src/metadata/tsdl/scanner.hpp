/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_TSDL_SCANNER_HPP
#define BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_TSDL_SCANNER_HPP

#include <stdio.h>

#include "ast.hpp"

#ifndef YY_TYPEDEF_YY_SCANNER_T
#    define YY_TYPEDEF_YY_SCANNER_T
typedef void *yyscan_t;
#endif

struct ctf_scanner_scope;
struct ctf_scanner_scope
{
    struct ctf_scanner_scope *parent;
    GHashTable *classes;
};

struct ctf_scanner
{
    explicit ctf_scanner(const bt2c::Logger& parentLogger) :
        logger {parentLogger, "PLUGIN/CTF/META/PARSER"}
    {
    }

    bt2c::Logger logger;
    yyscan_t scanner {};
    ctf_ast *ast = nullptr;
    ctf_scanner_scope root_scope {};
    ctf_scanner_scope *cs = nullptr;
    struct objstack *objstack = nullptr;
};

struct ctf_scanner *ctf_scanner_alloc(const bt2c::Logger& parentLogger);

void ctf_scanner_free(struct ctf_scanner *scanner);

int ctf_scanner_append_ast(struct ctf_scanner *scanner, FILE *input);

static inline struct ctf_ast *ctf_scanner_get_ast(struct ctf_scanner *scanner)
{
    return scanner->ast;
}

int is_type(struct ctf_scanner *scanner, const char *id);

#endif /* BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_TSDL_SCANNER_HPP */
