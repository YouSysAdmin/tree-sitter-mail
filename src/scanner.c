#include "tree_sitter/parser.h"

// A zero width token at the end of the file, so the last header needs no
// trailing line break.
enum TokenType {
  EOF_SENTINEL,
};

void *tree_sitter_mail_external_scanner_create(void) { return NULL; }

void tree_sitter_mail_external_scanner_destroy(void *payload) { (void)payload; }

unsigned tree_sitter_mail_external_scanner_serialize(void *payload, char *buffer) {
  (void)payload;
  (void)buffer;

  return 0;
}

void tree_sitter_mail_external_scanner_deserialize(void *payload, const char *buffer, unsigned length) {
  (void)payload;
  (void)buffer;
  (void)length;
}

bool tree_sitter_mail_external_scanner_scan(void *payload, TSLexer *lexer, const bool *valid_symbols) {
  (void)payload;
  if (valid_symbols[EOF_SENTINEL] && lexer->eof(lexer)) {
    lexer->result_symbol = EOF_SENTINEL;

    return true;
  }

  return false;
}
