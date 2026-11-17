/**
 * @file Mail message headers, for reading transit and authentication headers
 * @license MIT
 */

/// <reference types="tree-sitter-cli/dsl" />
// @ts-check

// A line break ends a header, a line break followed by white space folds
// the value onto the next line and is treated as white space.
const CRLF = /\r?\n/;
const HS = /[ \t]+/;
const FOLD = /\r?\n[ \t]+/;

// Text of a value that may fold, used where the value has no structure.
const FOLDED = /[^ \t\r\n][^\r\n]*(?:\r?\n[ \t]+[^\r\n]*)*/;

/**
 * Builds a case insensitive pattern for a field name.
 *
 * @param {string} word
 * @returns {RegExp}
 */
function ci(word) {
  return new RegExp(
    [...word]
      .map((c) => {
        if (/[a-zA-Z]/.test(c)) {
          return `[${c.toLowerCase()}${c.toUpperCase()}]`;
        }

        // Digits must stay plain, an escaped one reads as a back reference.
        return /[0-9]/.test(c) ? c : `\\${c}`;
      })
      .join(''),
  );
}

/**
 * A label token matching any of the field names, case insensitive.
 *
 * @param {...string} words
 * @returns {RuleOrLiteral}
 */
function label(...words) {
  return token(prec(1, choice(...words.map(ci))));
}

/**
 * A label token matching any field name that starts with the prefix.
 *
 * @param {string} word
 * @returns {RegExp}
 */
function prefix(word) {
  return new RegExp(ci(word).source + '[A-Za-z0-9_-]+');
}

/**
 * One or more rules separated by a semicolon, with an optional trailing one.
 *
 * @param {RuleOrLiteral} rule
 * @returns {RuleOrLiteral}
 */
function semiSep(rule) {
  return seq(optional(rule), repeat(seq(';', optional(rule))));
}

module.exports = grammar({
  name: 'mail',

  extras: (_$) => [HS, token(prec(1, FOLD))],

  externals: ($) => [$._eof],

  rules: {
    source_file: ($) => seq(optional($.headers), optional($._body)),

    headers: ($) => repeat1($._header),

    _header: ($) =>
      choice(
        $.header_address,
        $.header_subject,
        $.header_date,
        $.header_msgid,
        $.header_received,
        $.header_auth,
        $.header_spf,
        $.header_signature,
        $.header_content,
        $.header_ms,
        $.header_id,
        $.header_spam,
        $.header_ip,
        $.header_list,
        $.header_flag,
        $.header_opaque,
        $.header_other,
      ),

    // Addresses

    header_address: ($) => seq($.label_address, ':', optional($.address_list), $._eol),

    label_address: (_$) =>
      label(
        'From',
        'Sender',
        'To',
        'Cc',
        'Bcc',
        'Reply-To',
        'Delivered-To',
        'Return-Path',
        'Envelope-To',
        'X-Original-To',
        'Resent-From',
        'Resent-To',
        'Resent-Cc',
        'Resent-Sender',
        'Disposition-Notification-To',
        'Return-Receipt-To',
        'Errors-To',
        'Bounces-To',
        'Mail-Followup-To',
        'Mail-Reply-To',
        'X-Envelope-From',
        'X-Envelope-To',
        'X-Original-Sender',
        'X-Original-From',
        'X-Failed-Recipients',
        'X-Sender',
        'X-Receiver',
        'X-BeenThere',
      ),

    address_list: ($) => seq($.mailbox, repeat(seq(',', $.mailbox))),

    mailbox: ($) => choice(seq(optional($.display_name), $.angle_addr), $.address),

    display_name: ($) => repeat1(choice($.atom, $.quoted_string, $.encoded_word)),

    angle_addr: ($) => seq('<', optional($.address), '>'),

    // Subject

    header_subject: ($) => seq($.label_subject, ':', repeat(choice($.encoded_word, $.subject_text)), $._eol),

    label_subject: (_$) => label('Subject', 'Resent-Subject', 'Thread-Topic'),

    subject_text: (_$) => token(prec(-1, /[^ \t\r\n]+/)),

    // Date

    header_date: ($) => seq($.label_date, ':', optional($.date_time), $._eol),

    label_date: (_$) => label('Date', 'Resent-Date', 'Delivery-Date'),

    date_time: (_$) => token(prec(1, /[0-9A-Za-z][^\r\n]*/)),

    // Message identifiers

    header_msgid: ($) => seq($.label_msgid, ':', repeat($.msgid), $._eol),

    label_msgid: (_$) =>
      label('Message-ID', 'In-Reply-To', 'References', 'Resent-Message-ID', 'Original-Message-ID'),

    msgid: (_$) => token(/<[^<>\s]*>/),

    // Trace

    header_received: ($) => seq($.label_received, ':', optional($.trace), $._eol),

    label_received: (_$) => label('Received', 'X-Received', 'X-Original-Received'),

    trace: ($) => seq(repeat1(choice($.trace_clause, $.comment)), optional(seq(';', optional($.date_time)))),

    trace_clause: ($) =>
      prec.right(seq($.trace_keyword, repeat1(choice($.angle_addr, $.ip_address, $.trace_value, $.comment)))),

    trace_keyword: (_$) => token(prec(2, choice(ci('from'), ci('by'), ci('via'), ci('with'), ci('id'), ci('for')))),

    trace_value: (_$) => token(/[^\s()<>;]+/),

    // Authentication results

    header_auth: ($) => seq($.label_auth, ':', semiSep($._auth_item), $._eol),

    label_auth: (_$) =>
      label('Authentication-Results', 'ARC-Authentication-Results', 'X-Authentication-Results'),

    // One token for every bare word of a value, so the parser, not the
    // lexer, decides what a word is from the character that follows it.
    _auth_word: (_$) => token(/[^\s;()=]+/),

    _auth_item: ($) => choice($.auth_method, $.authserv_id),

    authserv_id: ($) => $._auth_word,

    auth_method: ($) => seq($.auth_name, '=', $.auth_result, repeat(choice($.comment, $.auth_property))),

    auth_name: ($) => $._auth_word,

    auth_result: ($) => $._auth_word,

    auth_property: ($) => seq($.property_name, '=', $.property_value),

    property_name: ($) => $._auth_word,

    property_value: ($) => choice($.address, $.ip_address, $.quoted_string, $._auth_word),

    // SPF results, the value starts with the result instead of a server id

    header_spf: ($) =>
      seq(
        $.label_spf,
        ':',
        $.auth_result,
        repeat(choice($.comment, $.auth_property)),
        optional(';'),
        $._eol,
      ),

    label_spf: (_$) => label('Received-SPF', 'X-Received-SPF'),

    // Signatures

    header_signature: ($) => seq($.label_signature, ':', semiSep($._signature_tag), $._eol),

    label_signature: (_$) =>
      label(
        'DKIM-Signature',
        'DomainKey-Signature',
        'X-Google-DKIM-Signature',
        'X-Google-Original-DKIM-Signature',
        'ARC-Seal',
        'ARC-Message-Signature',
      ),

    _signature_tag: ($) => choice($.signature_blob, $.signature_tag),

    signature_blob: ($) => seq($.blob_name, '=', optional($.blob_value)),

    blob_name: (_$) => token(prec(2, choice(ci('b'), ci('bh'), ci('fh'), ci('p')))),

    blob_value: (_$) => token(/[A-Za-z0-9+\/=]+(?:\r?\n[ \t]+[A-Za-z0-9+\/=]+)*/),

    signature_tag: ($) => seq($.tag_name, '=', optional($.tag_value)),

    tag_name: (_$) => token(/[A-Za-z][A-Za-z0-9_-]*/),

    tag_value: (_$) => token(/[^\s;]+(?:\r?\n[ \t]+[^\s;]+)*/),

    // Content

    header_content: ($) => seq($.label_content, ':', semiSep($._content_item), $._eol),

    label_content: (_$) => token(prec(1, choice(ci('MIME-Version'), /[Cc][Oo][Nn][Tt][Ee][Nn][Tt]-[A-Za-z][A-Za-z0-9-]*/))),

    _content_item: ($) => choice($.mime_type, $.parameter, $.content_value),

    mime_type: (_$) => token(prec(2, /[A-Za-z0-9!#$&^_.+-]+\/[A-Za-z0-9!#$&^_.+-]+/)),

    parameter: ($) => seq($.param_name, '=', $.param_value),

    param_name: ($) => $._content_word,

    param_value: ($) => choice($.quoted_string, $._content_word),

    content_value: ($) => $._content_word,

    _content_word: (_$) => token(/[^\s;="]+/),

    // Identifiers a sending service stamps on a message

    header_id: ($) => seq($.label_id, ':', repeat($.id_value), $._eol),

    label_id: (_$) =>
      label(
        'X-Mailyard-Email-Id',
        'X-Mailyard-Project-Id',
        'X-Mailyard-Event',
        'X-Mailyard-Relay-Node',
        'X-Message-ID',
        'X-Request-Id',
        'X-Correlation-Id',
        'X-PM-Message-Id',
        'X-Campaign-Id',
      ),

    id_value: (_$) => token(/[^\s]+/),

    // Microsoft filtering reports, a list of KEY:value pairs

    header_ms: ($) => seq($.label_ms, ':', semiSep($.ms_tag), $._eol),

    label_ms: (_$) =>
      label(
        'X-Forefront-Antispam-Report',
        'X-Forefront-Antispam-Report-Untrusted',
        'X-Microsoft-Antispam',
        'X-Microsoft-Antispam-Untrusted',
        'X-Microsoft-Antispam-Mailbox-Delivery',
      ),

    ms_tag: ($) => seq($.ms_name, ':', optional($.ms_value)),

    ms_name: (_$) => token(/[A-Za-z][A-Za-z0-9_-]*/),

    ms_value: ($) => choice($.ip_address, $.ms_text),

    ms_text: (_$) => token(/[^;\s][^;\r\n]*(?:\r?\n[ \t]+[^;\r\n]*)*/),

    // Spam and virus verdicts, a verdict word and key=value pairs

    header_spam: ($) => seq($.label_spam, ':', repeat(choice($.spam_tag, $.spam_word)), $._eol),

    label_spam: (_$) =>
      label(
        'X-Spam',
        'X-Spam-Status',
        'X-Spam-Flag',
        'X-Spam-Level',
        'X-Spam-Score',
        'X-Spam-Bar',
        'X-Spam-Result',
        'X-Spam-Checker-Version',
        'X-Rspamd-Score',
        'X-Rspamd-Action',
        'X-Rspamd-Server',
        'X-Rspamd-Queue-Id',
        'X-Virus-Scanned',
        'X-Virus-Status',
        'X-Quarantine-ID',
        'X-MS-Exchange-Organization-SCL',
        'X-MS-Exchange-Organization-PCL',
        'X-MS-Exchange-Organization-AuthAs',
        'X-MS-Exchange-Organization-AuthMechanism',
        'X-MS-Exchange-Organization-AuthSource',
      ),

    spam_tag: ($) => seq($.spam_name, '=', $.spam_value),

    spam_name: ($) => $._spam_word,

    spam_value: ($) => $._spam_word,

    spam_word: ($) => $._spam_word,

    _spam_word: (_$) => token(/[^\s=]+/),

    // Headers that name the machine a message came from

    header_ip: ($) => seq($.label_ip, ':', repeat(choice($.ip_address, $.comment, $.ip_text)), $._eol),

    label_ip: (_$) =>
      label(
        'X-Originating-IP',
        'X-Originating-Ip',
        'X-Sender-IP',
        'X-Source-IP',
        'X-SourceIP',
        'X-Client-IP',
        'X-Remote-IP',
        'X-Real-IP',
        'X-Peer-IP',
        'X-Connecting-IP',
        'X-Forwarded-For',
      ),

    ip_text: (_$) => token(/[^\s()]+/),

    // Bulk mail, the addresses and URIs offered to the reader

    header_list: ($) => seq($.label_list, ':', repeat(choice($.list_uri, ',', $.list_text)), $._eol),

    label_list: (_$) =>
      token(
        prec(
          1,
          choice(
            prefix('List-'),
            ci('Feedback-ID'),
            ci('X-Feedback-ID'),
            ci('X-Report-Abuse'),
            ci('Abuse-Reports-To'),
            ci('X-CSA-Complaints'),
          ),
        ),
      ),

    list_uri: ($) => seq('<', $.uri, '>'),

    uri: (_$) => token(/[^<>\s]+/),

    list_text: (_$) => token(/[^\s<>,]+/),

    // Flags a client or a filter sets

    header_flag: ($) => seq($.label_flag, ':', repeat($.flag_value), $._eol),

    label_flag: (_$) =>
      label(
        'Precedence',
        'Auto-Submitted',
        'Sensitivity',
        'Importance',
        'X-Priority',
        'X-MSMail-Priority',
        'X-MS-Has-Attach',
        'X-Auto-Response-Suppress',
        'X-Mailyard-Sandbox',
        'X-Mailyard-Sandbox-Retention',
        'X-Mailyard-Disable-Tracking',
        'X-Mailyard-Timestamp',
      ),

    flag_value: (_$) => token(/[^\s]+/),

    // Values with nothing to read in them, kept out of the way

    header_opaque: ($) => seq($.label_opaque, ':', optional($.opaque), $._eol),

    label_opaque: (_$) =>
      token(
        prec(
          1,
          choice(
            prefix('X-Gm-'),
            prefix('X-Google-Smtp-'),
            prefix('X-Sonic-'),
            prefix('X-YMail-'),
            prefix('X-Proofpoint-'),
            prefix('X-Mimecast-'),
            prefix('X-Barracuda-'),
            prefix('X-SG-'),
            prefix('X-Mailgun-'),
            prefix('X-MC-'),
            prefix('X-SES-'),
            prefix('X-ZohoMail-'),
            prefix('X-Yandex-'),
            prefix('X-Mailru-'),
            prefix('X-Amazon-'),
            prefix('X-MS-Exchange-CrossTenant-'),
            prefix('X-MS-Office365-'),
            ci('X-Microsoft-Antispam-Message-Info'),
            ci('X-MS-Exchange-Organization-Network-Message-Id'),
            ci('X-MS-Exchange-Transport-CrossTenantHeadersStamped'),
            ci('Thread-Index'),
            ci('X-Entity-ID'),
            ci('X-Attachment-Id'),
            ci('X-Mailyard-Signature'),
            ci('X-Mailyard-Auth'),
          ),
        ),
      ),

    opaque: (_$) => token(FOLDED),

    // Anything else

    header_other: ($) => seq($.label_other, ':', optional($.unstructured), $._eol),

    label_other: (_$) => token(/[!-9;-~]+/),

    unstructured: (_$) => token(FOLDED),

    // Shared

    comment: ($) => seq('(', repeat(choice($.comment, $.address, $.ip_address, $.comment_text)), ')'),

    comment_text: (_$) => token(prec(-1, /[^()\s]+/)),

    address: (_$) => token(prec(1, /[^\s<>,;:"()\[\]@]+@[^\s<>,;:"()\[\]@]+/)),

    ip_address: (_$) =>
      token(
        prec(
          2,
          choice(
            /\[?(?:[0-9]{1,3}\.){3}[0-9]{1,3}\]?/,
            /\[?(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\]?/,
          ),
        ),
      ),

    atom: (_$) => token(/[^\s<>,;:"()\[\]\\=]+/),

    quoted_string: (_$) => token(/"(?:[^"\\\r\n]|\\.)*"/),

    encoded_word: (_$) => token(prec(3, /=\?[^?\s]+\?[A-Za-z]\?[^?\s]*\?=/)),

    _eol: ($) => choice(token(CRLF), $._eof),

    // Body, parsed only far enough to show where a MIME part starts

    // The body starts at the empty line that ends the header block, so a
    // header is never read as body text.
    _body: ($) => seq(token(CRLF), repeat(choice($.mime_part, $.body_line, token(CRLF)))),

    mime_part: ($) => seq($.boundary, $._eol, repeat($._header)),

    boundary: (_$) => token(prec(1, /--[^\s]+/)),

    body_line: (_$) => token(prec(-2, /[^\r\n]+/)),
  },
});
