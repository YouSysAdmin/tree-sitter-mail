# tree-sitter-mail

Tree-sitter grammar for mail messages, written for the Duck editor. It
parses the header block in detail and the body only far enough to show
where a MIME part begins.

Structured values:

- `Received` and `X-Received`: the from, by, via, with, id and for clauses,
  parenthesised remarks, IP addresses and the trailing date
- `Authentication-Results`, `ARC-Authentication-Results` and `Received-SPF`:
  the server id, every method with its result, and the properties of a method
- `DKIM-Signature`, `DomainKey-Signature`, `ARC-Seal` and
  `ARC-Message-Signature`: the tag list, with the base64 blobs apart from the
  rest
- addresses, dates, message ids, encoded words and `Content-*` parameters

Everything else becomes a field name and an unstructured value. Folded
values are joined through white space, so a continuation line is never
read as a new header.

## Development

```
npx tree-sitter-cli@0.25.10 generate
npx tree-sitter-cli@0.25.10 test
```

`src/parser.c` is checked in, the editor compiles it through
`dk grammar build`. Highlighting queries live in the editor repository
under `runtime/queries/mail`.
