/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#ifndef BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_TSDL_AST_HPP
#define BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_TSDL_AST_HPP

#include <memory>

#include <glib.h>
#include <stdint.h>
#include <stdio.h>

#include <babeltrace2/babeltrace.h>

#include "common/assert.h"
#include "common/list.h"
#include "cpp-common/bt2/self-component-port.hpp"
#include "cpp-common/bt2/trace-ir.hpp"
#include "cpp-common/bt2c/logging.hpp"
#include "cpp-common/vendor/fmt/format.h" /* IWYU pragma: keep */

#include "../../clk-cls-cfg.hpp"
#include "ctf-meta.hpp"

// the parameter name (of the reentrant 'yyparse' function)
// data is a pointer to a 'SParserParam' structure
//#define YYPARSE_PARAM	scanner

struct ctf_node;
struct ctf_parser;
struct ctf_visitor_generate_ir;

#define EINCOMPLETE 1000

#define FOREACH_CTF_NODES(F)                                                                       \
    F(NODE_UNKNOWN)                                                                                \
    F(NODE_ROOT)                                                                                   \
    F(NODE_ERROR)                                                                                  \
    F(NODE_EVENT)                                                                                  \
    F(NODE_STREAM)                                                                                 \
    F(NODE_ENV)                                                                                    \
    F(NODE_TRACE)                                                                                  \
    F(NODE_CLOCK)                                                                                  \
    F(NODE_CALLSITE)                                                                               \
    F(NODE_CTF_EXPRESSION)                                                                         \
    F(NODE_UNARY_EXPRESSION)                                                                       \
    F(NODE_TYPEDEF)                                                                                \
    F(NODE_TYPEALIAS_TARGET)                                                                       \
    F(NODE_TYPEALIAS_ALIAS)                                                                        \
    F(NODE_TYPEALIAS)                                                                              \
    F(NODE_TYPE_SPECIFIER)                                                                         \
    F(NODE_TYPE_SPECIFIER_LIST)                                                                    \
    F(NODE_POINTER)                                                                                \
    F(NODE_TYPE_DECLARATOR)                                                                        \
    F(NODE_FLOATING_POINT)                                                                         \
    F(NODE_INTEGER)                                                                                \
    F(NODE_STRING)                                                                                 \
    F(NODE_ENUMERATOR)                                                                             \
    F(NODE_ENUM)                                                                                   \
    F(NODE_STRUCT_OR_VARIANT_DECLARATION)                                                          \
    F(NODE_VARIANT)                                                                                \
    F(NODE_STRUCT)

enum node_type
{
#define ENTRY(S) S,
    FOREACH_CTF_NODES(ENTRY)
#undef ENTRY
};

inline const char *format_as(enum node_type type) noexcept
{
    switch (type) {
#define ENTRY(S)                                                                                   \
case S:                                                                                            \
    return G_STRINGIFY(S);

        FOREACH_CTF_NODES(ENTRY)
#undef ENTRY
    }

    bt_common_abort();
}

enum ctf_unary
{
    UNARY_UNKNOWN = 0,
    UNARY_STRING,
    UNARY_SIGNED_CONSTANT,
    UNARY_UNSIGNED_CONSTANT,
    UNARY_SBRAC,
};

inline const char *format_as(ctf_unary value) noexcept
{
    switch (value) {
    case UNARY_UNKNOWN:
        return "UNARY_UNKNOWN";

    case UNARY_STRING:
        return "UNARY_STRING";

    case UNARY_SIGNED_CONSTANT:
        return "UNARY_SIGNED_CONSTANT";

    case UNARY_UNSIGNED_CONSTANT:
        return "UNARY_UNSIGNED_CONSTANT";

    case UNARY_SBRAC:
        return "UNARY_SBRAC";
    }

    bt_common_abort();
}

enum ctf_unary_link
{
    UNARY_LINK_UNKNOWN = 0,
    UNARY_DOTLINK,
    UNARY_ARROWLINK,
    UNARY_DOTDOTDOT,
};

enum ctf_typedec
{
    TYPEDEC_UNKNOWN = 0,
    TYPEDEC_ID,     /* identifier */
    TYPEDEC_NESTED, /* (), array or sequence */
};

inline const char *format_as(ctf_typedec value) noexcept
{
    switch (value) {
    case TYPEDEC_UNKNOWN:
        return "TYPEDEC_UNKNOWN";

    case TYPEDEC_ID:
        return "TYPEDEC_ID";

    case TYPEDEC_NESTED:
        return "TYPEDEC_NESTED";
    }

    bt_common_abort();
}

enum ctf_typespec
{
    TYPESPEC_UNKNOWN = 0,
    TYPESPEC_VOID,
    TYPESPEC_CHAR,
    TYPESPEC_SHORT,
    TYPESPEC_INT,
    TYPESPEC_LONG,
    TYPESPEC_FLOAT,
    TYPESPEC_DOUBLE,
    TYPESPEC_SIGNED,
    TYPESPEC_UNSIGNED,
    TYPESPEC_BOOL,
    TYPESPEC_COMPLEX,
    TYPESPEC_IMAGINARY,
    TYPESPEC_CONST,
    TYPESPEC_ID_TYPE,
    TYPESPEC_FLOATING_POINT,
    TYPESPEC_INTEGER,
    TYPESPEC_STRING,
    TYPESPEC_STRUCT,
    TYPESPEC_VARIANT,
    TYPESPEC_ENUM,
};

inline const char *format_as(ctf_typespec value) noexcept
{
    switch (value) {
    case TYPESPEC_UNKNOWN:
        return "TYPESPEC_UNKNOWN";

    case TYPESPEC_VOID:
        return "TYPESPEC_VOID";

    case TYPESPEC_CHAR:
        return "TYPESPEC_CHAR";

    case TYPESPEC_SHORT:
        return "TYPESPEC_SHORT";

    case TYPESPEC_INT:
        return "TYPESPEC_INT";

    case TYPESPEC_LONG:
        return "TYPESPEC_LONG";

    case TYPESPEC_FLOAT:
        return "TYPESPEC_FLOAT";

    case TYPESPEC_DOUBLE:
        return "TYPESPEC_DOUBLE";

    case TYPESPEC_SIGNED:
        return "TYPESPEC_SIGNED";

    case TYPESPEC_UNSIGNED:
        return "TYPESPEC_UNSIGNED";

    case TYPESPEC_BOOL:
        return "TYPESPEC_BOOL";

    case TYPESPEC_COMPLEX:
        return "TYPESPEC_COMPLEX";

    case TYPESPEC_IMAGINARY:
        return "TYPESPEC_IMAGINARY";

    case TYPESPEC_CONST:
        return "TYPESPEC_CONST";

    case TYPESPEC_ID_TYPE:
        return "TYPESPEC_ID_TYPE";

    case TYPESPEC_FLOATING_POINT:
        return "TYPESPEC_FLOATING_POINT";

    case TYPESPEC_INTEGER:
        return "TYPESPEC_INTEGER";

    case TYPESPEC_STRING:
        return "TYPESPEC_STRING";

    case TYPESPEC_STRUCT:
        return "TYPESPEC_STRUCT";

    case TYPESPEC_VARIANT:
        return "TYPESPEC_VARIANT";

    case TYPESPEC_ENUM:
        return "TYPESPEC_ENUM";
    }

    bt_common_abort();
}

struct ctf_node
{
    /*
     * Parent node is only set on demand by specific visitor.
     */
    struct ctf_node *parent;
    struct bt_list_head siblings;
    struct bt_list_head tmp_head;
    unsigned int lineno;
    /*
     * We mark nodes visited in the generate-ir phase (last
     * phase). We only mark the 1-depth level nodes as visited
     * (never the root node, and not their sub-nodes). This allows
     * skipping already visited nodes when doing incremental
     * metadata append.
     */
    int visited;

    enum node_type type;
    union
    {
        struct
        {
        } unknown;
        struct
        {
            /*
             * Children nodes are ctf_expression, field_class_def,
             * field_class_alias and field_class_specifier_list.
             */
            struct bt_list_head declaration_list;
            struct bt_list_head trace;
            struct bt_list_head env;
            struct bt_list_head stream;
            struct bt_list_head event;
            struct bt_list_head clock;
            struct bt_list_head callsite;
        } root;
        struct
        {
            /*
             * Children nodes are ctf_expression, field_class_def,
             * field_class_alias and field_class_specifier_list.
             */
            struct bt_list_head declaration_list;
        } event;
        struct
        {
            /*
             * Children nodes are ctf_expression, field_class_def,
             * field_class_alias and field_class_specifier_list.
             */
            struct bt_list_head declaration_list;
        } stream;
        struct
        {
            /*
             * Children nodes are ctf_expression, field_class_def,
             * field_class_alias and field_class_specifier_list.
             */
            struct bt_list_head declaration_list;
        } env;
        struct
        {
            /*
             * Children nodes are ctf_expression, field_class_def,
             * field_class_alias and field_class_specifier_list.
             */
            struct bt_list_head declaration_list;
        } trace;
        struct
        {
            /*
             * Children nodes are ctf_expression, field_class_def,
             * field_class_alias and field_class_specifier_list.
             */
            struct bt_list_head declaration_list;
        } clock;
        struct
        {
            /*
             * Children nodes are ctf_expression, field_class_def,
             * field_class_alias and field_class_specifier_list.
             */
            struct bt_list_head declaration_list;
        } callsite;
        struct
        {
            struct bt_list_head left;  /* Should be string */
            struct bt_list_head right; /* Unary exp. or type */
        } ctf_expression;
        struct
        {
            ctf_unary type;
            union
            {
                /*
                 * string for identifier, id_type, keywords,
                 * string literals and character constants.
                 */
                char *string;
                int64_t signed_constant;
                uint64_t unsigned_constant;
                struct ctf_node *sbrac_exp;
            } u;
            ctf_unary_link link;
        } unary_expression;
        struct
        {
            struct ctf_node *field_class_specifier_list;
            struct bt_list_head field_class_declarators;
        } field_class_def;
        /* new type is "alias", existing type "target" */
        struct
        {
            struct ctf_node *field_class_specifier_list;
            struct bt_list_head field_class_declarators;
        } field_class_alias_target;
        struct
        {
            struct ctf_node *field_class_specifier_list;
            struct bt_list_head field_class_declarators;
        } field_class_alias_name;
        struct
        {
            struct ctf_node *target;
            struct ctf_node *alias;
        } field_class_alias;
        struct
        {
            ctf_typespec type;
            /* For struct, variant and enum */
            struct ctf_node *node;
            const char *id_type;
        } field_class_specifier;
        struct
        {
            /* list of field_class_specifier */
            struct bt_list_head head;
        } field_class_specifier_list;
        struct
        {
            unsigned int const_qualifier;
        } pointer;
        struct
        {
            struct bt_list_head pointers;
            ctf_typedec type;
            union
            {
                char *id;
                struct
                {
                    /* typedec has no pointer list */
                    struct ctf_node *field_class_declarator;
                    /*
                     * unary expression (value) or
                     * field_class_specifier_list.
                     */
                    struct bt_list_head length;
                    /* for abstract type declarator */
                    unsigned int abstract_array;
                } nested;
            } u;
            struct ctf_node *bitfield_len;
        } field_class_declarator;
        struct
        {
            /* Children nodes are ctf_expression. */
            struct bt_list_head expressions;
        } floating_point;
        struct
        {
            /* Children nodes are ctf_expression. */
            struct bt_list_head expressions;
        } integer;
        struct
        {
            /* Children nodes are ctf_expression. */
            struct bt_list_head expressions;
        } string;
        struct
        {
            char *id;
            /*
             * Range list or single value node. Contains unary
             * expressions.
             */
            struct bt_list_head values;
        } enumerator;
        struct
        {
            char *enum_id;
            /*
             * Either NULL, or points to unary expression or
             * field_class_specifier_list.
             */
            struct ctf_node *container_field_class;
            struct bt_list_head enumerator_list;
            int has_body;
        } _enum;
        struct
        {
            struct ctf_node *field_class_specifier_list;
            struct bt_list_head field_class_declarators;
        } struct_or_variant_declaration;
        struct
        {
            char *name;
            char *choice;
            /*
             * list of field_class_def, field_class_alias and
             * declarations
             */
            struct bt_list_head declaration_list;
            int has_body;
        } variant;
        struct
        {
            char *name;
            /*
             * list of field_class_def, field_class_alias and
             * declarations
             */
            struct bt_list_head declaration_list;
            int has_body;
            struct bt_list_head min_align; /* align() attribute */
        } _struct;
    } u;
};

struct ctf_ast
{
    struct ctf_node root;
};

const char *node_type(struct ctf_node *node);

struct ctf_visitor_generate_ir
{
    using UP = std::unique_ptr<ctf_visitor_generate_ir>;

    explicit ctf_visitor_generate_ir(
        const ctf::src::ClkClsCfg& clkClsCfgParam,
        const bt2::OptionalBorrowedObject<bt2::SelfComponent> selfCompParam,
        bt2c::Logger loggerParam) noexcept :

        logger {std::move(loggerParam)},
        selfComp {selfCompParam}, clkClsCfg {clkClsCfgParam}
    {
    }

    ~ctf_visitor_generate_ir();

    bt2c::Logger logger;

    bt2::OptionalBorrowedObject<bt2::SelfComponent> selfComp;

    /* Trace IR trace class being filled (owned by this) */
    bt2::TraceClass::Shared trace_class;

    /* CTF meta trace being filled (owned by this) */
    struct ctf_trace_class *ctf_tc = nullptr;

    /* Current declaration scope (top of the stack) (owned by this) */
    struct ctx_decl_scope *current_scope = nullptr;

    /* True if trace declaration is visited */
    bool is_trace_visited = false;

    /* True if this is an LTTng trace */
    bool is_lttng = false;

    ctf::src::ClkClsCfg clkClsCfg;
};

ctf_visitor_generate_ir::UP
ctf_visitor_generate_ir_create(const ctf::src::ClkClsCfg& clkClsCfg,
                               bt2::OptionalBorrowedObject<bt2::SelfComponent> selfComp,
                               const bt2c::Logger& parentLogger);

bt2::TraceClass::Shared
ctf_visitor_generate_ir_get_ir_trace_class(struct ctf_visitor_generate_ir *visitor);

struct ctf_trace_class *
ctf_visitor_generate_ir_borrow_ctf_trace_class(struct ctf_visitor_generate_ir *visitor);

int ctf_visitor_generate_ir_visit_node(struct ctf_visitor_generate_ir *visitor,
                                       struct ctf_node *node);

int ctf_visitor_semantic_check(int depth, struct ctf_node *node, const bt2c::Logger& logger);

int ctf_visitor_parent_links(int depth, struct ctf_node *node, const bt2c::Logger& logger);

static inline char *ctf_ast_concatenate_unary_strings(struct bt_list_head *head)
{
    int i = 0;
    GString *str;
    struct ctf_node *node;

    str = g_string_new(NULL);
    BT_ASSERT(str);

    bt_list_for_each_entry (node, head, siblings) {
        char *src_string;

        if (node->type != NODE_UNARY_EXPRESSION || node->u.unary_expression.type != UNARY_STRING ||
            !((node->u.unary_expression.link != UNARY_LINK_UNKNOWN) ^ (i == 0))) {
            goto error;
        }

        switch (node->u.unary_expression.link) {
        case UNARY_DOTLINK:
            g_string_append(str, ".");
            break;
        case UNARY_ARROWLINK:
            g_string_append(str, "->");
            break;
        case UNARY_DOTDOTDOT:
            g_string_append(str, "...");
            break;
        default:
            break;
        }

        src_string = node->u.unary_expression.u.string;
        g_string_append(str, src_string);
        i++;
    }

    /* Destroys the container, returns the underlying string */
    return g_string_free(str, FALSE);

error:
    /* This always returns NULL */
    return g_string_free(str, TRUE);
}

#ifndef BT_COMP_LOG_CUR_LVL
#    define BT_AST_LOG_LEVEL_UNUSED_ATTR __attribute__((unused))
#else
#    define BT_AST_LOG_LEVEL_UNUSED_ATTR
#endif

static inline int ctf_ast_get_unary_uuid(struct bt_list_head *head, bt_uuid_t uuid,
                                         const bt2c::Logger& logger)
{
    int i = 0;
    int ret = 0;
    struct ctf_node *node;

    bt_list_for_each_entry (node, head, siblings) {
        int uexpr_type = node->u.unary_expression.type;
        int uexpr_link = node->u.unary_expression.link;
        const char *src_string;

        if (node->type != NODE_UNARY_EXPRESSION || uexpr_type != UNARY_STRING ||
            uexpr_link != UNARY_LINK_UNKNOWN || i != 0) {
            ret = -EINVAL;
            goto end;
        }

        src_string = node->u.unary_expression.u.string;
        ret = bt_uuid_from_str(src_string, uuid);
        if (ret) {
            BT_CPPLOGE_APPEND_CAUSE_SPEC(logger, "Cannot parse UUID: uuid=\"{}\"", src_string);
            goto end;
        }
    }

end:
    return ret;
}

#endif /* BABELTRACE_PLUGINS_CTF_COMMON_SRC_METADATA_TSDL_AST_HPP */
