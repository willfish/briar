/* SPDX-License-Identifier: AGPL-3.0-only */
/* Derived from TruffleHog v3.97.2, pkg/detectors/gocanvas/gocanvas.go. */
#include "detectors.h"
#include "captures.h"
#include "findings.h"
#include "email_pattern.h"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/SAX2.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

typedef struct { br_regex *key, *email; } canvas_patterns;
typedef enum { XML_DECODED, XML_DROP, XML_UNSUPPORTED, XML_RESOURCE } canvas_xml;
typedef enum { CANVAS_ABORT = -1, CANVAS_KEEP, CANVAS_SKIP } canvas_outcome;
typedef struct { bool resource, unsupported, closed; int syntax; } xml_problem;

static int fail(char **error, const char *message)
{
    if (error) *error = strdup(message);
    return -1;
}

static size_t space_width(br_slice s)
{
    if (!s.len) return 0;
    unsigned char c = s.data[0];
    if (c == ' ' || (c >= 9 && c <= 13)) return 1;
    if (s.len >= 2 && c == 0xc2 && (s.data[1] == 0x85 || s.data[1] == 0xa0)) return 2;
    if (s.len >= 3 && ((c == 0xe1 && s.data[1] == 0x9a && s.data[2] == 0x80) ||
        (c == 0xe2 && s.data[1] == 0x80 && ((s.data[2] >= 0x80 && s.data[2] <= 0x8a) ||
        s.data[2] == 0xa8 || s.data[2] == 0xa9 || s.data[2] == 0xaf)) ||
        (c == 0xe2 && s.data[1] == 0x81 && s.data[2] == 0x9f) ||
        (c == 0xe3 && s.data[1] == 0x80 && s.data[2] == 0x80))) return 3;
    return 0;
}

static br_slice trim(br_slice s)
{
    size_t n;
    while ((n = space_width(s))) { s.data += n; s.len -= n; }
    for (;;) {
        bool cut = false;
        for (n = 1; n <= 3 && n <= s.len; ++n)
            if (space_width((br_slice){s.data + s.len - n, n}) == n) { s.len -= n; cut = true; break; }
        if (!cut) return s;
    }
}

static bool unreserved(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~';
}

static int form_body(br_slice email, br_bytes *body)
{
    static const char prefix[] = "username=", hex[] = "0123456789ABCDEF";
    size_t size = sizeof(prefix) - 1;
    for (size_t i = 0; i < email.len; ++i) {
        size_t width = unreserved(email.data[i]) || email.data[i] == ' ' ? 1 : 3;
        if (size > SIZE_MAX - width) return -1;
        size += width;
    }
    unsigned char *data = malloc(size);
    if (!data) return -1;
    size_t at = sizeof(prefix) - 1; memcpy(data, prefix, at);
    for (size_t i = 0; i < email.len; ++i) {
        unsigned char c = email.data[i];
        if (unreserved(c)) data[at++] = c;
        else if (c == ' ') data[at++] = '+';
        else { data[at++] = '%'; data[at++] = hex[c >> 4]; data[at++] = hex[c & 15]; }
    }
    *body = (br_bytes){data, size};
    return 0;
}

/* Only codes whose meaning implies a Go encoding/xml syntax error. Ambiguous
 * whole-document/namespace/DTD failures are NOT ordinary candidate drops. */
static bool definite_syntax(int code)
{
    switch (code) {
    case XML_ERR_TAG_NAME_MISMATCH:
    case XML_ERR_TAG_NOT_FINISHED: case XML_ERR_COMMENT_NOT_FINISHED:
    case XML_ERR_CDATA_NOT_FINISHED: case XML_ERR_INVALID_CHAR:
    case XML_ERR_INVALID_ENCODING: case XML_ERR_INVALID_CHARREF:
    case XML_ERR_INVALID_HEX_CHARREF: case XML_ERR_INVALID_DEC_CHARREF:
    case XML_ERR_UNDECLARED_ENTITY: return true;
    default: return false;
    }
}

static void xml_error(void *user, const xmlError *error)
{
    xml_problem *p = user;
    if (error->code == XML_ERR_NO_MEMORY || error->code == XML_ERR_RESOURCE_LIMIT ||
        error->code == XML_ERR_NAME_TOO_LONG || error->code == XML_ERR_INTERNAL_ERROR ||
        error->code == XML_ERR_SYSTEM) p->resource = true;
    else if (error->level >= XML_ERR_ERROR) {
        if (!p->closed && definite_syntax(error->code)) p->syntax = error->code;
        else p->unsupported = true;
    }
}

static void end_element(void *ctx, const xmlChar *local, const xmlChar *prefix, const xmlChar *uri)
{
    xmlParserCtxt *parser = ctx;
    xmlNode *node = xmlCtxtGetNode(parser);
    xml_problem *problem = xmlCtxtGetPrivate(parser);
    if (node && node->parent && node->parent->type == XML_DOCUMENT_NODE) problem->closed = true;
    xmlSAX2EndElementNs(ctx, local, prefix, uri);
}

static xmlParserErrors deny_resource(void *user, const char *url, const char *public_id,
    xmlResourceType type, xmlParserInputFlags flags, xmlParserInput **out)
{
    (void)url; (void)public_id; (void)type; (void)flags;
    ((xml_problem *)user)->unsupported = true;
    *out = NULL;
    return XML_IO_LOAD_ERROR;
}

/* Detect a DTD even when a later parser failure discards its document. Skip
 * comments, CDATA and PIs so harmless literal markers do not widen the gap. */
static bool has_dtd(br_slice body)
{
    for (size_t i = 0; i < body.len;) {
        const char *end = NULL; size_t opening = 0;
        if (body.len - i >= 4 && !memcmp(body.data + i, "<!--", 4)) { end = "-->"; opening = 4; }
        else if (body.len - i >= 9 && !memcmp(body.data + i, "<![CDATA[", 9)) { end = "]]>"; opening = 9; }
        else if (body.len - i >= 2 && !memcmp(body.data + i, "<?", 2)) { end = "?>"; opening = 2; }
        else if (body.len - i >= 9 && !memcmp(body.data + i, "<!DOCTYPE", 9)) return true;
        if (end) {
            size_t at = br_slice_find(body, (br_slice){(const unsigned char *)end, strlen(end)}, i + opening);
            if (at == SIZE_MAX) return false;
            i = at + strlen(end);
        } else ++i;
    }
    return false;
}

static bool named(const xmlNode *node, const char *name)
{
    return node->type == XML_ELEMENT_NODE && !xmlStrcmp(node->name, BAD_CAST name);
}

/* copyValue's int path: raw empty is zero, but trimmed-empty is ParseInt error.
 * Use only immediate text/CDATA; descendant text and comments are ignored. */
static canvas_xml decode_int(const xmlNode *node)
{
    size_t len = 0;
    for (const xmlNode *p = node->children; p; p = p->next) {
        if ((p->type != XML_TEXT_NODE && p->type != XML_CDATA_SECTION_NODE) || !p->content) continue;
        size_t n = (size_t)xmlStrlen(p->content);
        if (len > SIZE_MAX - n) return XML_RESOURCE;
        len += n;
    }
    if (!len) return XML_DECODED;
    unsigned char *text = malloc(len);
    if (!text) return XML_RESOURCE;
    size_t at = 0;
    for (const xmlNode *p = node->children; p; p = p->next) {
        if ((p->type != XML_TEXT_NODE && p->type != XML_CDATA_SECTION_NODE) || !p->content) continue;
        size_t n = (size_t)xmlStrlen(p->content); memcpy(text + at, p->content, n); at += n;
    }
    br_slice s = trim((br_slice){text, len});
    size_t i = 0; bool negative = s.len && s.data[0] == '-';
    if (s.len && (s.data[0] == '+' || negative)) ++i;
    bool valid = i < s.len;
    uint64_t value = 0, limit = (uint64_t)INT64_MAX + (negative ? 1u : 0u);
    for (; valid && i < s.len; ++i) {
        unsigned char c = s.data[i];
        if (c < '0' || c > '9' || value > (limit - (c - '0')) / 10) valid = false;
        else value = value * 10 + (c - '0');
    }
    free(text);
    return valid ? XML_DECODED : XML_DROP;
}

static canvas_xml decode_response(br_slice body, bool *has_error)
{
    *has_error = false;
    if (body.len > INT_MAX) return XML_RESOURCE;
    if (!body.len) return XML_DROP;
    /* Go accepts leading character data, but whitespace-only input is EOF. */
    bool only_xml_space = true;
    for (size_t i = 0; body.data && i < body.len; ++i)
        if (body.data[i] != ' ' && body.data[i] != '\t' && body.data[i] != '\r' && body.data[i] != '\n') { only_xml_space = false; break; }
    if (body.data && only_xml_space) return XML_DROP;
    if (!body.data) return XML_RESOURCE;
    xmlParserCtxt *parser = xmlNewParserCtxt();
    if (!parser) return XML_RESOURCE;
    xml_problem problem = {0};
    xmlCtxtSetPrivate(parser, &problem);
    parser->sax->endElementNs = end_element;
    xmlCtxtSetErrorHandler(parser, xml_error, &problem);
    xmlCtxtSetResourceLoader(parser, deny_resource, &problem);
    xmlDoc *doc = xmlCtxtReadMemory(parser, (const char *)body.data, (int)body.len,
        NULL, "UTF-8", XML_PARSE_NO_XXE | XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING);
    /* NOERROR/NOWARNING can suppress the context callback as well as output. */
    const xmlError *last = xmlCtxtGetLastError(parser);
    if (last) xml_error(&problem, last);
    const xmlChar *encoding = xmlCtxtGetDeclaredEncoding(parser), *version = xmlCtxtGetVersion(parser);
    bool source_bad_decl = (encoding && xmlStrcasecmp(encoding, BAD_CAST "UTF-8")) ||
        (version && xmlStrcmp(version, BAD_CAST "1.0"));
    bool dtd = has_dtd(body) || (doc && (doc->intSubset || doc->extSubset));
    canvas_xml outcome = XML_DECODED;
    if (problem.resource) outcome = XML_RESOURCE;
    else if (source_bad_decl) outcome = XML_DROP;
    else if (dtd || problem.unsupported) outcome = XML_UNSUPPORTED;
    else if (!doc || problem.syntax) outcome = problem.syntax ? XML_DROP : XML_UNSUPPORTED;
    xmlNode *root = doc ? xmlDocGetRootElement(doc) : NULL;
    if (outcome == XML_DECODED && !root) outcome = XML_DROP;
    /* Arbitrary root accepted, including Error itself. Only direct local-name
     * Error children append entries. Like xml.Unmarshal, stop at the first
     * ErrorCode failure; later fields must not allocate or replace its outcome. */
    for (xmlNode *e = outcome == XML_DECODED ? root->children : NULL;
         outcome == XML_DECODED && e; e = e->next) {
        if (!named(e, "Error")) continue;
        *has_error = true;
        for (xmlNode *code = e->children; outcome == XML_DECODED && code; code = code->next) {
            if (!named(code, "ErrorCode")) continue;
            outcome = decode_int(code);
        }
    }
    xmlFreeDoc(doc); xmlFreeParserCtxt(parser);
    return outcome;
}

static canvas_outcome verify_canvas(const br_scan_ctx *ctx, br_slice key, br_slice email,
                                    br_result *result, char **error)
{
    br_bytes body = {0};
    if (form_body(email, &body)) { fail(error, "cannot construct GoCanvas form body"); return CANVAS_ABORT; }
    if (!ctx) { free(body.data); return CANVAS_SKIP; }
    char auth[52]; memcpy(auth, "Bearer ", 7); memcpy(auth + 7, key.data, key.len); auth[7 + key.len] = 0;
    const br_header headers[] = {{"Content-Type", "application/x-www-form-urlencoded"}, {"Authorization", auth}};
    const br_http_request request = {
        .method = "GET", .url = "https://www.gocanvas.com/apiv2/forms.xml",
        .headers = headers, .nheaders = 2, .body = {body.data, body.len},
        .profile = BR_HTTP_SANE, .detector_type = result->detector_type,
    };
    br_http_response response = {0}; char *transport_error = NULL;
    canvas_outcome outcome = CANVAS_KEEP;
    /* Whole mixed Do errors are suppressed, never classified by diagnostics.
     * ANY ReadAll error retains false, even with empty/complete XML bytes. */
    if (!br_http_send(ctx, &request, &response, &transport_error) && !response.body_error) {
        bool has_error = false;
        canvas_xml decoded = decode_response(response.body, &has_error);
        if (decoded == XML_DROP) outcome = CANVAS_SKIP;
        else if (decoded == XML_RESOURCE || decoded == XML_UNSUPPORTED) {
            fail(error, decoded == XML_RESOURCE ? "GoCanvas XML resource failure" : "unsupported: GoCanvas XML outside strict complete UTF-8 XML 1.0 subset");
            outcome = CANVAS_ABORT;
        } else result->verified = response.status >= 200 && response.status < 300 && !has_error;
    }
    /* Ordinary ABI1 request synthesis ends at send return. Only original body,
     * URL and auth remain borrowed through release; never retain shared UA. */
    br_http_release(ctx, &response);
    free(transport_error); free(body.data);
    return outcome;
}

static int scan_canvas(const br_detector *detector, const br_scan_ctx *ctx, bool verify,
                       br_slice input, br_results *out, char **error)
{
    if (error) *error = NULL;
    if (!detector || !detector->state || !out || (!input.data && input.len)) return fail(error, "invalid GoCanvas scan");
    const canvas_patterns *compiled = detector->state;
    if (!compiled->key || !compiled->email) return fail(error, "uninitialized GoCanvas patterns");
    br_captures keys = {0}, emails = {0}; char *owned_error = NULL;
    size_t original_len = out->len;
    int rc = br_captures_find(compiled->key, input, &keys, false, &owned_error);
    /* Group 1, NOT the outer match or IPv4 subgroups. Reachable email edges
     * cannot be whitespace, so unique-before-trim equals unique-after-TrimSpace. */
    if (!rc) rc = br_captures_find(compiled->email, input, &emails, true, &owned_error);
    for (size_t e = 0; !rc && e < emails.len; ++e) for (size_t k = 0; !rc && k < keys.len; ++k) {
        br_result result = {0}; canvas_outcome outcome = CANVAS_KEEP;
        br_slice key = trim(br_captures_at(&keys, k));
        if (key.len != 44 || br_finding_key_bytes(&result, detector->type, key, "key")) {
            fail(&owned_error, "cannot create GoCanvas result"); outcome = CANVAS_ABORT;
        }
        if (outcome == CANVAS_KEEP && verify) outcome = verify_canvas(ctx, key, trim(br_captures_at(&emails, e)), &result, &owned_error);
        if (outcome == CANVAS_KEEP && br_results_push(out, &result)) {
            fail(&owned_error, "cannot append GoCanvas result"); outcome = CANVAS_ABORT;
        }
        br_result_clear(&result);
        if (outcome == CANVAS_ABORT) rc = -1;
    }
    if (rc) while (out->len > original_len) br_result_clear(&out->items[--out->len]);
    br_captures_clear(&keys); br_captures_clear(&emails);
    if (error) *error = owned_error; else free(owned_error);
    return rc ? -1 : 0;
}

static canvas_patterns patterns;
static const char *const keywords[] = {"gocanvas"};
static const br_detector canvas = {
    .type = 714, .version = 0, .name = "GoCanvas", .custom_name = "",
    .description = "GoCanvas is a platform for automating business processes using mobile forms. GoCanvas API keys can be used to access and modify data within the GoCanvas platform.",
    .keywords = keywords, .nkeywords = 1,
    .max_secret_size = -1, .start_offset = -1, .max_credential_span = 1024,
    .state = &patterns, .scan = scan_canvas,
};

int br_gocanvas_init(const br_detector **out, char **error)
{
    if (error) *error = NULL;
    if (!out) return fail(error, "invalid GoCanvas detector output");
    *out = NULL;
    if (!patterns.key && br_regex_compile_prefixed(keywords, 1, "\\b([0-9A-Za-z/+]{43}=[ \\r\\n]{1})", &patterns.key, error)) return -1;
    if (!patterns.email && br_regex_compile_prefixed(keywords, 1, br_email_pattern, &patterns.email, error)) return -1;
    *out = &canvas;
    return 0;
}
