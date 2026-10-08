#!/usr/bin/env python3
"""Real packet tests in private mount and network namespaces. Never touch host rules."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time


def run(*args, input=None, expected=0):
    r = subprocess.run(args, input=input, text=True, capture_output=True, timeout=30)
    assert r.returncode == expected, (args, r.returncode, r.stdout, r.stderr)
    return r.stdout


def main():
    assert os.geteuid() == 0, "Use sudo; this test requires mount/network namespace capabilities."
    binary = str(Path(sys.argv[1]).resolve())
    if len(sys.argv) == 2:
        subprocess.run(["unshare", "--mount", "--net", "--propagation", "private",
                        sys.executable, __file__, binary, "--inside",
                        os.readlink("/proc/self/ns/mnt"), os.readlink("/proc/self/ns/net")], check=True)
        return
    assert len(sys.argv) == 5 and sys.argv[2] == "--inside"
    assert os.readlink("/proc/self/ns/mnt") != sys.argv[3]
    assert os.readlink("/proc/self/ns/net") != sys.argv[4]
    for path in ("/etc", "/var/lib", "/run"):
        run("mount", "-t", "tmpfs", "-o", "mode=755", "tmpfs", path)
    run("ip", "link", "set", "lo", "up")
    run("ip", "netns", "add", "cm-test-client")
    run("ip", "link", "add", "cm-server", "type", "veth", "peer", "name", "cm-client")
    run("ip", "link", "set", "cm-client", "netns", "cm-test-client")
    run("ip", "addr", "add", "192.0.2.1/24", "dev", "cm-server")
    run("ip", "-6", "addr", "add", "2001:db8:1::1/64", "dev", "cm-server", "nodad")
    run("ip", "link", "set", "cm-server", "up")
    for family, address in [([], "192.0.2.2/24"), (["-6"], "2001:db8:1::2/64")]:
        run("ip", "-n", "cm-test-client", *family, "addr", "add", address,
            "dev", "cm-client", *("nodad",) if family else ())
    run("ip", "-n", "cm-test-client", "link", "set", "cm-client", "up")
    run("ip", "-n", "cm-test-client", "link", "set", "lo", "up")

    def cm(*args, expected=0):
        return run(binary, "--no-rollback", *args, expected=expected)

    server_code = """
import selectors,socket,sys
s=selectors.DefaultSelector()
for port in map(int,sys.argv[1:]):
 x=socket.socket(socket.AF_INET6);x.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
 x.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,0);x.bind(('::',port));x.listen()
 s.register(x,selectors.EVENT_READ,'listener')
u=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);u.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,0)
u.bind(('::',8053));s.register(u,selectors.EVENT_READ,'udp')
print('ready',flush=True)
while True:
 for key,event in s.select():
  if key.data=='listener':
   conn,addr=key.fileobj.accept();conn.sendall(b'ok');s.register(conn,selectors.EVENT_READ,'client')
  elif key.data=='udp':
   data,addr=key.fileobj.recvfrom(1024);key.fileobj.sendto(data,addr)
  else:
   try:data=key.fileobj.recv(1024)
   except OSError:data=b''
   if data:
    try:key.fileobj.sendall(data)
    except OSError:pass
   else:s.unregister(key.fileobj);key.fileobj.close()
"""
    servers = [
        subprocess.Popen([sys.executable, "-u", "-c", server_code, "8000", "8001", "9000"],
                         stdout=subprocess.PIPE, text=True),
        subprocess.Popen(["ip", "netns", "exec", "cm-test-client", sys.executable,
                          "-u", "-c", server_code, "9443"],
                         stdout=subprocess.PIPE, text=True)]
    for server in servers:
        assert server.stdout.readline().strip() == "ready"
    client_code = """
import socket,sys
family=socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET
udp=sys.argv[3]=='udp'
s=socket.socket(family,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM);s.settimeout(.7)
s.connect((sys.argv[1],int(sys.argv[2])))
if udp:s.send(b'ok')
assert s.recv(2)==b'ok'
s.close()
"""

    def connect(address, port=8000, allowed=True, outbound=False, udp=False):
        prefix = [] if outbound else ["ip", "netns", "exec", "cm-test-client"]
        r = subprocess.run([*prefix, sys.executable, "-c", client_code, address,
                            str(port), "udp" if udp else "tcp"], capture_output=True, timeout=5)
        assert (r.returncode == 0) == allowed, (address, port, allowed, outbound, r.stderr)

    def snapshot(table):
        return json.loads(run("nft", "--json", "list", "table", "inet", table))["nftables"]

    def handle():
        return next(x["table"]["handle"] for x in snapshot("command_center") if "table" in x)

    def ban_handle():
        return next(x["table"]["handle"] for x in snapshot("command_center_bans") if "table" in x)

    raw_syn = r"""
import socket,struct,sys
src,dst,port,offset=sys.argv[1],sys.argv[2],int(sys.argv[3]),int(sys.argv[4])
family=socket.AF_INET6 if ':' in src else socket.AF_INET
s=socket.socket(family,socket.SOCK_RAW,socket.IPPROTO_TCP)
for i in range(10):
 tcp=struct.pack('!HHLLBBHHH',41000+offset+i,port,i+1,0,5<<4,2,65535,0,0)
 addresses=socket.inet_pton(family,src)+socket.inet_pton(family,dst)
 pseudo=addresses+(struct.pack('!I3xB',len(tcp),6) if family==socket.AF_INET6 else struct.pack('!BBH',0,6,len(tcp)))
 words=struct.unpack('!%dH'%((len(pseudo)+len(tcp))//2),pseudo+tcp)
 total=sum(words)
 while total>>16:total=(total&65535)+(total>>16)
 tcp=tcp[:16]+struct.pack('!H',(~total)&65535)+tcp[18:]
 s.sendto(tcp,(dst,0))
"""

    def syn_burst(src, dst, port, offset, outbound):
        prefix = [] if outbound else ["ip", "netns", "exec", "cm-test-client"]
        run(*prefix, sys.executable, "-c", raw_syn, src, dst, str(port), str(offset))
        time.sleep(.1)

    def dropped(rule_id, family):
        return sum(expr["counter"]["packets"]
                   for obj in snapshot("command_center")
                   if obj.get("rule", {}).get("chain") == f"gate{family}_{rule_id}"
                   for expr in obj["rule"]["expr"] if "counter" in expr)

    foreign = """table inet untouched {
 chain input { type filter hook input priority 10; policy accept; tcp dport 9000 drop; }
 chain forward { type filter hook forward priority 0; policy accept; }
}
"""
    try:
        run("nft", "-f", "-", input=foreign)
        before = snapshot("untouched")
        cm("init")
        cm("apply")  # Equivalent to the loader unit; no system bus in this fixture.
        connect("192.0.2.1")
        connect("2001:db8:1::1", 8001)
        connect("192.0.2.1", 9000, allowed=False)
        assert snapshot("untouched") == before
        cm("allow", "8000/tcp")
        cm("allow", "8001/tcp")
        cm("default", "in", "deny")
        assert not json.loads(cm("status", "--json"))["drift"]
        connect("192.0.2.1")
        connect("2001:db8:1::1")
        cm("deny", "8000/tcp", "--from", "192.0.2.2")
        connect("192.0.2.1")  # First match is the earlier allow.
        cm("move", "3", "before", "1")
        connect("192.0.2.1", allowed=False)
        connect("2001:db8:1::1")
        cm("delete", "3")
        cm("ban", "192.0.2.2", "--for", "2s")
        connect("192.0.2.1", allowed=False)
        connect("2001:db8:1::1")
        time.sleep(2.2)
        connect("192.0.2.1")
        cm("unban", "192.0.2.2")
        cm("limit", "8000/tcp", "--rate", "1/minute", "--burst", "1")
        connect("192.0.2.1")
        connect("192.0.2.1", allowed=False)
        connect("2001:db8:1::1")
        connect("2001:db8:1::1", allowed=False)
        assert not json.loads(cm("status", "--json"))["drift"]
        old_handle = handle()
        cm("ban", "203.0.113.8", "--for", "permanent")
        assert handle() == old_handle, "Ban reconciliation reset connection meters."
        old_ban_handle = ban_handle()
        cm("ban", "203.0.113.9", "--for", "10m", "--scope", "ssh")
        assert ban_handle() == old_ban_handle, "Single-ban update rebuilt the ban table."
        cm("ban", "203.0.113.9", "--for", "20m", "--scope", "all")
        cm("unban", "203.0.113.9")
        assert ban_handle() == old_ban_handle, "Ban refresh/rescope/removal rebuilt the ban table."
        cm("service", "set", "unused", "12345/tcp")
        cm("logging", "level", "warning")
        cm("service", "set", "unused", "12346/tcp", "--stage")
        # This fixture has no systemd: an unchanged guard requires no service job.
        cm("reload")
        assert handle() == old_handle
        assert not Path("/var/lib/command-center/pending.json").exists()
        connect("192.0.2.1", allowed=False)
        connect("2001:db8:1::1", allowed=False)
        run("nft", "delete", "element", "inet", "command_center_bans", "manual_all4", "{", "203.0.113.8", "}")
        assert json.loads(cm("status", "--json", expected=3))["ban_membership_drift"]
        cm("reload")
        assert handle() == old_handle
        assert not json.loads(cm("status", "--json"))["ban_membership_drift"]
        run("nft", "add", "chain", "inet", "command_center_bans", "unexpected")
        assert json.loads(cm("status", "--json", expected=3))["kernel_drift"]
        cm("reload")
        assert handle() == old_handle, "Repairing ban structure reset connection meters."
        Path("/run/command-center/active.json").unlink()
        assert not json.loads(cm("status", "--json", expected=3))["activation_known"]
        cm("allow", "9002/tcp", expected=1)
        assert handle() == old_handle
        cm("apply")
        cm("delete", "4")
        connect("192.0.2.1")
        cm("service", "set", "testdns", "8053/both")
        cm("allow", "testdns")
        connect("192.0.2.1", 8053, udp=True)
        connect("2001:db8:1::1", 8053, udp=True)
        cm("reject", "8001/tcp", "--from", "192.0.2.2")
        cm("move", "6", "before", "2")
        connect("192.0.2.1", 8001, allowed=False)
        cm("delete", "6")
        run("nft", "add", "rule", "inet", "command_center", "input", "tcp", "dport", "9001", "accept")
        assert json.loads(cm("status", "--json", expected=3))["kernel_drift"]
        config = Path("/etc/command-center/config.json")
        old = config.read_bytes()
        cm("allow", "9002/tcp", expected=1)
        assert config.read_bytes() == old
        cm("reload")
        assert snapshot("untouched") == before
        assert not json.loads(cm("status", "--json"))["drift"]
        # A CM accept cannot override another table's drop.
        run("nft", "add", "rule", "inet", "untouched", "input", "tcp", "dport", "8001", "drop")
        connect("192.0.2.1", 8001, allowed=False)
        run("nft", "delete", "table", "inet", "untouched")
        run("nft", "-f", "-", input=foreign)
        config.write_text("{invalid desired file")
        cm("apply")
        connect("192.0.2.1")
        cm("config", "restore")
        cm("allow", "out", "9443/tcp", "--to", "192.0.2.2")
        cm("default", "out", "deny")
        connect("192.0.2.2", 9443, outbound=True)
        connect("2001:db8:1::2", 9443, outbound=True, allowed=False)
        cm("allow", "out", "9443/tcp", "--to", "2001:db8:1::2", "--family", "6")
        connect("2001:db8:1::2", 9443, outbound=True)
        persistent = socket.create_connection(("192.0.2.2", 9443), timeout=1)
        assert persistent.recv(2) == b"ok"
        # Deplete a large bucket, idle beyond the old 2s expiry, then measure earned tokens.
        for outbound, port in ((False, 8000), (True, 9443)):
            cm("limit", *(["out"] if outbound else []), f"{port}/tcp", "--rate", "1/second", "--burst", "10")
            rule_id = json.loads(cm("rules", "--json"))[-1]["id"]
            endpoints = ((4, "192.0.2.1", "192.0.2.2"), (6, "2001:db8:1::1", "2001:db8:1::2"))
            for family, server, client in endpoints:
                src, dst = (server, client) if outbound else (client, server)
                syn_burst(src, dst, port, 0, outbound)
                assert dropped(rule_id, family) == 0, "Initial burst was not available."
            time.sleep(3.2)
            for family, server, client in endpoints:
                src, dst = (server, client) if outbound else (client, server)
                syn_burst(src, dst, port, 100, outbound)
                count = dropped(rule_id, family)
                assert 4 <= count <= 8, ("Bucket reset before replenishment", outbound, family, count)
            cm("delete", str(rule_id))
        # Compile isolation via its preview, disabling its journal daemon in this no-systemd fixture.
        isolation = json.loads(cm("profile", "show", "isolation", "--ssh-port", "8000/tcp", "--json"))
        isolation["guard"]["enabled"] = False
        config.write_text(json.dumps(isolation))
        cm("reload")
        connect("192.0.2.1")  # Incoming management replies still work.
        connect("2001:db8:1::1")
        connect("192.0.2.1", 8001, allowed=False)
        connect("192.0.2.2", 9443, outbound=True, allowed=False)
        persistent.settimeout(.7)
        persistent.sendall(b"xx")
        try:
            data = persistent.recv(2)
        except socket.timeout:
            data = b""
        assert data != b"xx", "Isolation preserved an established outbound session."
        persistent.close()
        # Log throttling must never turn a blocked verdict into an accept.
        cm("logging", "packets", "high")
        cm("check")
        burst_code = """
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.settimeout(.4)
for _ in range(100):s.sendto(b'ok',('192.0.2.1',8053))
try:
 data,peer=s.recvfrom(1024)
 raise AssertionError('A blocked packet passed after the logging quota was exhausted')
except socket.timeout:pass
"""
        run("ip", "netns", "exec", "cm-test-client", sys.executable, "-c", burst_code)
        for _ in range(3):
            connect("192.0.2.1", 8001, allowed=False)
        cm("ban", "192.0.2.2", "--for", "permanent", "--scope", "ssh")
        connect("192.0.2.1", allowed=False)
        cm("unban", "192.0.2.2")
        connect("192.0.2.1")
        # A previous boot with startup disabled has no active policy and permits saved edits.
        checkpoint = Path("/var/lib/command-center/committed.json")
        prior = json.loads(checkpoint.read_text())
        prior["boot_id"] = "previous-boot"
        checkpoint.write_text(json.dumps(prior))
        Path("/run/command-center/active.json").unlink()
        run("nft", "delete", "table", "inet", "command_center")
        run("nft", "delete", "table", "inet", "command_center_bans")
        assert not json.loads(cm("status", "--json"))["active"]
        cm("allow", "9002/tcp")
        assert not json.loads(cm("status", "--json"))["policy_table_present"]
        cm("apply")
        cm("suspend")
        assert not json.loads(cm("status", "--json"))["policy_table_present"]
        assert snapshot("untouched")
        print("Native IPv4/IPv6, passive start, rule ordering, limits, bans, UDP, reject, drift, "
              "coexistence, egress, isolation, log throttling and scoped cleanup passed.")
    finally:
        for server in servers:
            server.terminate()
            server.wait(timeout=5)
        run("ip", "netns", "delete", "cm-test-client")


if __name__ == "__main__":
    main()
