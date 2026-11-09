# Fount Mail test messages

Test mail for the broker's fetch, verify and intake code. The rules these files
test are in the Fount repo at `docs/features/fount-fleet/message-format.md`.
Section numbers below (§3, §6) point there.

**Every file here was constructed, not captured.** We built them on 2026-11-08 from
what each mail client is known to write. No real mail client sent them, and nobody
fetched them from a real mailbox. They're close enough to test parsing, but a real
client can differ in small ways, such as spacing, header order or the date format.
The section [Replace with real captures](#replace-with-real-captures) lists which
ones to swap first.

## Names and domains

All names are made up, and every address uses a reserved example domain.

| Domain | Stands for |
|---|---|
| `example.com` | The owner's firm, Whitlock & Reyes CPA. It also stands in for Google's and Microsoft's servers in `Received:` lines and `Message-ID`s, such as `mail.example.com` and `*.prod.example.com` |
| `example.org` | Clients and vendors: Marcus Feld and Lena Ortiz at Halvorsen Marine, and Northwind Supply |
| `example.net` | Fount's mail domain, standing in for `fountbox.com`. The worker is `ap.whitlockcpa@example.net` |

The owner is Dana Whitlock, `dana@example.com`. The reply token
`q7m2x4k9v3t8n6p1r5w0z2y4ha` in `ap.whitlockcpa+<token>@example.net` is a
placeholder. It isn't valid in any test key set.

IP addresses come from the documentation ranges, such as `198.51.100.0/24`.

## What the files are like

- Each `.eml` file is the raw message the edge stores: CRLF line endings, no bare
  CR or LF, 7-bit only, and no line over 998 octets. The edge adds no headers of its
  own, so these are the bytes from the sending server.
- None of them have a `DKIM-Signature`. A test that needs a signature should sign
  the file with its own test key and put the new header first. Nothing else changes.
  Until a test does that, the sidecar's `assume_verdict` gives the verdict that
  intake should use.
- The attachments are small but real files: PDFs that open, an `.xlsx` that opens,
  a PNG and a CSV. Their SHA-256 hashes are in the sidecars.

## Layout and conventions

```text
testdata/mail/
  forwards/<name>.eml           one inbound message
  forwards/<name>.json          sidecar: envelope, assumed verdict, expected results
  forwards/<name>.message.md    the message.md that intake should write (§3)
  replies/...                   the same three files for each reply
  replies/fount-question.eml    the message Fount sent that the replies answer
  threads/<NN-case>/
    case.json                   inputs and expected threading results, in order
    NN-in-<key>.eml             a message the worker received
    NN-out-<key>.eml            a message Fount sent
```

**File names** are `<client>-<case>` or `hostile-<case>`. The client is `gmail`,
`outlook`, `outlook-classic` or `apple`. A new capture keeps the name of the file it
replaces, and its sidecar's `provenance` becomes `"captured"`.

**Sidecar** (`<name>.json`):

| Field | Meaning |
|---|---|
| `provenance` | `constructed` or `captured` |
| `client` | Which mail client the file imitates |
| `kind` | `forward-inline`, `forward-attachment`, `new` or `reply` |
| `replace_with_capture` | `true` if a real capture should replace this file |
| `covers` | What the fixture tests |
| `envelope` | `sender` and `recipient`, the SMTP envelope. To seal a test object, frame them as the edge does: `senderLen(2) \| sender \| recipientLen(2) \| recipient \| raw` |
| `edge_id`, `received_at` | Values to use for the edge ID and the edge clock. The edge ID is 32 lowercase hex characters |
| `assume_verdict` | The verifier's verdict, given as input, because the files aren't signed |
| `thread_headers` | `message_id`, `in_reply_to` and `references`, parsed by the §6.1 rules |
| `expect.note` | `status` is `certain`, `none` or `uncertain`, plus the `marker` found, the note `text` when certain, and the `reason` when uncertain |
| `expect.body_source` | `plain` or `html`: which version `message.md` shows first |
| `expect.flags` | Short flag names from §3.6 |
| `expect.attachments` | In MIME order, depth first: the saved `path`, the decoded `raw_name`, the `content_type`, the `size`, the `sha256`, `found_in`, `inline`, and the `content_id` if there is one |
| `context` | Replies only: the earlier messages in the thread, which message is being answered, and which ones the session already holds |

**Golden `message.md`.** The section order, the headings, the lines under "Fount's
checks", and the text inside each fenced block are what the spec requires. When you
compare, trim trailing spaces and collapse runs of blank lines inside fenced blocks.
The HTML-to-text whitespace in `hostile-alt-mismatch` is only roughly specified, so
compare that fixture's fenced text after collapsing all whitespace.

**`case.json`** lists the messages in arrival order. For each message,
`assume_verdict` and `token_thread` are inputs: the verifier's verdict and the
thread the broker found from the reply token. Everything under `expect` is output:

| Field | Meaning |
|---|---|
| `message_key` | The parsed `Message-ID`, or `edge:<edge id>` if there's no usable one |
| `in_reply_to`, `references` | Parsed and cleaned ids (§6.1) |
| `parent` | The message this one replies to, from the headers (§6.2) |
| `thread` | A label such as `T1`. Real thread IDs are random. `null` means the message is in no thread |
| `new_thread` | Whether this message started its thread |
| `answers` | The message in this thread that it answers, or `null` if unknown |
| `links` | Other threads it links to: `{thread, via, kind}`, where `kind` is `names_message` or `shares_ancestor` |
| `candidate_thread` | For held mail only: the thread to show next to the "add" choice |
| `message_id_conflict` | `true` once a second message has used the same `Message-ID` |

## The fixtures

### Forwards

| Fixture | What it tests | Replace first? |
|---|---|---|
| `gmail-forward-plain` | Gmail web inline forward with a note. `References` and `In-Reply-To` name the forwarded message | yes |
| `gmail-forward-no-note` | Gmail forward with no note, so the standing instructions apply | yes |
| `gmail-forward-attachments` | Gmail forward carrying the original's PDF and xlsx | **yes** |
| `gmail-forward-nested` | Gmail wrapping an Outlook forward. Marcus's older note is data. A long invoice table, and a Cc line | **yes** |
| `gmail-forward-as-attachment` | Gmail "Forward as attachment": a `message/rfc822` part with a PDF inside it | **yes** |
| `gmail-new-request` | A new owner email with a CSV. No marker, so the whole body is the note | no |
| `outlook-forward-plain` | New Outlook or Outlook on the web: underscore rule, then From/Sent/To/Subject. Signature in the note. `Thread-Index`, and a `<style style="display:none">` element that hides no text | **yes** |
| `outlook-classic-forward-attachments` | Classic Outlook for Windows on an IMAP account: header block with no rule, Word HTML, a `cid:` signature image, and an xlsx named with an RFC 2047 encoded-word | **yes** |
| `outlook-forward-french` | French Outlook (`TR:`, `De :`). Fount doesn't recognize the marker, so the split is uncertain | yes |
| `apple-forward-plain` | Apple Mail: `> Begin forwarded message:`, U+202F before PM, no thread headers | **yes** |
| `apple-forward-attachments` | Apple Mail's split HTML around an inline PDF, with an RFC 2231 `filename*` | **yes** |
| `hostile-hidden-html` | Hidden HTML text in the note and in the forwarded part. After it's dropped, the two versions match | no |
| `hostile-alt-mismatch` | The forwarded vendor email names one bank in its plain text and another in its HTML | no |
| `hostile-attachment-names` | Right-to-left override, path traversal toward `.fount/FOUNT.md`, no name, duplicate names, `CON`, a name over 120 bytes, leading dots, and a backtick or pipe | no |

### Replies

Each reply answers `fount-question.eml`, the question Fount sent about
`gmail-forward-attachments`.

| Fixture | What it tests | Replace first? |
|---|---|---|
| `gmail-reply` | Gmail reply to the token address. The quote is exactly what Fount sent, so it's trimmed | **yes** |
| `gmail-reply-inline` | Owner answers between quoted lines, so the split is uncertain and nothing is trimmed | yes |
| `outlook-reply` | New Outlook `RE:` reply, quoted under a header block with no `>` | **yes** |
| `apple-reply-attachment` | Apple Mail reply with a CSV between two HTML fragments | **yes** |

### Threads

| Case | What it tests |
|---|---|
| `01-basic-reply` | A `thread_reply` with full headers |
| `02-reply-to-older` | A reply to an older message in the thread |
| `03-references-only` | No `In-Reply-To` |
| `04-in-reply-to-only` | No `References` |
| `05-no-thread-headers` | Neither header: joined by token, `answers` unknown |
| `06-malformed-ids` | Comments, an id broken by folding, `<>`, an id with no `@`, a bare id, repeats |
| `07-forwarded-again` | The same original forwarded twice: a new thread, linked by a shared ancestor |
| `08-owner-reply-without-token` | Owner reply to the plain address: a new thread, linked to the one it names |
| `09-stranger-reply` | A client replies all: held, with a candidate thread, never joined |
| `10-duplicate-message-id` | Two messages share a `Message-ID`, so that id links nothing |
| `11-missing-message-id` | No `Message-ID`: the message is keyed by its edge ID |
| `12-subject-only` | Same subject and no headers: no link, because subjects never thread |
| `13-self-and-loop-references` | The message names itself, and `References` repeats ids |
| `14-truncated-references` | A long thread whose `References` lost its middle |
| `15-multiple-in-reply-to` | Two ids in `In-Reply-To` |

## Replace with real captures

Real captures are needed before launch (design §11). Each one replaces the
constructed file with the same name. To make one:

1. Send it from the real client to a test mailbox that you control. Use the Fount
   dev mailbox once there is one.
2. Save the raw source. In Gmail use "Show original", then "Download original". In
   Outlook on the web use "View message source". In Apple Mail use "File", then
   "Save As", then "Raw Message Source".
3. Replace every real name, address, domain and IP with the ones above, and
   remove `DKIM-Signature`, `ARC-*`, `Authentication-Results` and any `X-Google-*` or
   `X-MS-Exchange-*` header that names a tenant. Edits break DKIM, which is fine,
   because the tests sign their own copies.
4. Re-save with CRLF line endings, then update the sidecar: set `provenance` to
   `captured`, then fix the hashes, the attachment names and the note text.

Things the constructed files guess at, which a capture will settle:

- Whether Apple Mail sets `References` or `In-Reply-To` on a forward. The files
  assume it doesn't.
- Whether Apple Mail's plain-text version puts `> ` before "Begin forwarded
  message:". The files assume it does.
- Whether Outlook on the web sets `References` on a forward. The files assume it does.
- The exact blank lines Gmail puts after its forwarded header block. The files use two.
- Whether classic Outlook's plain text shows `[cid:...]` for a signature image, and
  leaves a space at the end of the `From:` line.

## Not covered yet

These need real captures or real binary formats:

- `winmail.dat` (TNEF) from Outlook with rich text turned on
- Outlook for iOS and Android, iOS Mail, and Gmail's mobile apps
- Gmail "Forward all", which puts several forwarded messages in one email
- Calendar invites and replies, bounces (`multipart/report`), and auto-replies
- S/MIME or PGP signed mail
- Non-UTF-8 charsets, such as ISO-2022-JP or windows-1252, and raw 8-bit bodies.
  The edge doesn't advertise 8BITMIME
