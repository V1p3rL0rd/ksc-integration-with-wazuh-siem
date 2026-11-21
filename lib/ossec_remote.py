#!/usr/bin/env python3
"""Manage the KSC syslog <remote> block in Wazuh ossec.conf.

ossec.conf is not a strictly valid XML document (it may contain several
<ossec_config> roots), so the file is edited as text and only the managed
block between BEGIN/END markers is ever rewritten.

Subcommands:
  inspect  print JSON with the managed block state and conflicting blocks
  render   write a new ossec.conf with the managed block added/updated
  remove   write a new ossec.conf without the managed block

Exit codes: 0 ok, 2 usage/input error, 3 conflict (unmanaged block on the
same port/protocol; re-run with --adopt to take it over).
"""
import argparse
import ipaddress
import json
import re
import sys

MARK = "ksc-integration-with-wazuh-siem"
BEGIN = "<!-- BEGIN %s: KSC syslog receiver (managed by deploy.sh) -->" % MARK
END = "<!-- END %s -->" % MARK

MANAGED_RE = re.compile(
    r"[ \t]*" + re.escape(BEGIN) + r".*?" + re.escape(END) + r"[ \t]*\n?",
    re.DOTALL,
)
REMOTE_RE = re.compile(r"<remote>(.*?)</remote>", re.DOTALL)
TAG_RE = r"<{0}>\s*(.*?)\s*</{0}>"
COMMENT_BEFORE_RE = re.compile(r"(?:[ \t]*<!--(?:(?!-->).)*?-->[ \t]*\n)?[ \t]*$", re.DOTALL)


def tag(body, name, default=None):
    m = re.search(TAG_RE.format(re.escape(name)), body, re.DOTALL)
    return m.group(1).strip() if m else default


def remote_blocks(text):
    """Yield dicts for every <remote> block outside the managed block."""
    managed = MANAGED_RE.search(text)
    for m in REMOTE_RE.finditer(text):
        if managed and managed.start() <= m.start() < managed.end():
            continue
        body = m.group(1)
        connection = tag(body, "connection", "secure")
        default_proto = "udp" if connection == "syslog" else "tcp"
        protocols = [p.strip().lower() for p in tag(body, "protocol", default_proto).split(",") if p.strip()]
        default_port = "514" if connection == "syslog" else "1514"
        yield {
            "start": m.start(),
            "end": m.end(),
            "connection": connection,
            "port": tag(body, "port", default_port),
            "protocols": protocols,
            "allowed_ips": re.findall(TAG_RE.format("allowed-ips"), body, re.DOTALL),
            "text": m.group(0),
        }


def conflicts(text, port, proto):
    return [b for b in remote_blocks(text) if b["port"] == str(port) and proto in b["protocols"]]


def build_block(port, proto, ksc_ip, listen_ip, indent="  "):
    i2 = indent * 2
    return "\n".join([
        indent + BEGIN,
        indent + "<remote>",
        i2 + "<connection>syslog</connection>",
        i2 + "<port>%s</port>" % port,
        i2 + "<protocol>%s</protocol>" % proto,
        i2 + "<allowed-ips>%s/32</allowed-ips>" % ksc_ip,
        i2 + "<local_ip>%s</local_ip>" % listen_ip,
        indent + "</remote>",
        indent + END,
    ]) + "\n"


def remove_span_with_comment(text, start, end):
    """Remove text[start:end] plus a directly preceding comment mentioning KSC."""
    head = text[:start]
    m = COMMENT_BEFORE_RE.search(head)
    if m and "ksc" in m.group(0).lower():
        head = head[:m.start()]
    tail = text[end:]
    if tail.startswith("\n"):
        tail = tail[1:]
    return head.rstrip(" \t") + tail


def tidy(text):
    """Collapse runs of blank lines left around the managed block by edits."""
    return re.sub(re.escape(END) + r"\n(?:[ \t]*\n){2,}", END + "\n\n", text)


def render(text, port, proto, ksc_ip, listen_ip, adopt):
    new, found = _render(text, port, proto, ksc_ip, listen_ip, adopt)
    return (tidy(new) if new is not None else None), found


def _render(text, port, proto, ksc_ip, listen_ip, adopt):
    found = conflicts(text, port, proto)
    if found and not adopt:
        return None, found
    # remove adopted (unmanaged) blocks from the end to keep offsets valid
    for b in sorted(found, key=lambda x: x["start"], reverse=True):
        text = remove_span_with_comment(text, b["start"], b["end"])
    block = build_block(port, proto, ksc_ip, listen_ip)
    managed = MANAGED_RE.search(text)
    if managed:
        return text[:managed.start()] + block + text[managed.end():], found
    ends = [m.end() for m in re.finditer(r"</remote>[ \t]*\n?", text)]
    if ends:
        pos = ends[-1]
        prefix = "" if text[:pos].endswith("\n") else "\n"
        return text[:pos] + prefix + "\n" + block + text[pos:], found
    pos = text.find("</ossec_config>")
    if pos < 0:
        raise ValueError("no </remote> and no </ossec_config> found: not an ossec.conf?")
    return text[:pos] + block + "\n" + text[pos:], found


def remove(text):
    managed = MANAGED_RE.search(text)
    if not managed:
        return text, False
    head, tail = text[:managed.start()], text[managed.end():]
    # drop one blank line left between the previous element and the block
    if head.endswith("\n\n"):
        head = head[:-1]
    return head + tail, True


def valid_ip(value):
    try:
        ipaddress.IPv4Address(value)
    except ValueError:
        raise argparse.ArgumentTypeError("not an IPv4 address: %r" % value)
    return value


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("inspect", "render", "remove"):
        s = sub.add_parser(name)
        s.add_argument("--conf", required=True, help="path to ossec.conf")
        if name != "remove":
            s.add_argument("--port", type=int, required=True)
            s.add_argument("--proto", choices=("tcp", "udp"), required=True)
        if name == "render":
            s.add_argument("--ksc-ip", type=valid_ip, required=True)
            s.add_argument("--listen-ip", type=valid_ip, required=True)
            s.add_argument("--adopt", action="store_true", help="take over conflicting unmanaged blocks")
        if name != "inspect":
            s.add_argument("--out", required=True, help="where to write the new ossec.conf")
    a = p.parse_args(argv)

    try:
        with open(a.conf, encoding="utf-8") as f:
            text = f.read()
    except OSError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2

    if a.cmd == "inspect":
        managed = MANAGED_RE.search(text)
        found = conflicts(text, a.port, a.proto)
        json.dump({
            "managed": bool(managed),
            "managed_text": managed.group(0) if managed else "",
            "conflicts": [{k: b[k] for k in ("connection", "port", "protocols", "allowed_ips", "text")} for b in found],
        }, sys.stdout, ensure_ascii=False, indent=2)
        print()
        return 0

    if a.cmd == "render":
        try:
            new, found = render(text, a.port, a.proto, a.ksc_ip, a.listen_ip, a.adopt)
        except ValueError as e:
            print("error: %s" % e, file=sys.stderr)
            return 2
        if new is None:
            for b in found:
                print("conflict: unmanaged <remote> on %s/%s:\n%s" % (b["port"], ",".join(b["protocols"]), b["text"]),
                      file=sys.stderr)
            return 3
    else:
        new, _ = remove(text)

    with open(a.out, "w", encoding="utf-8") as f:
        f.write(new)
    return 0


if __name__ == "__main__":
    sys.exit(main())
