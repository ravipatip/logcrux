from pathlib import Path

import pytest

from logcrux.parsers.apache_access import ApacheAccessParser
from logcrux.parsers.auditd import AuditdParser
from logcrux.parsers.caddy import CaddyParser
from logcrux.parsers.celery import CeleryParser
from logcrux.parsers.coredns import CoreDNSParser
from logcrux.parsers.cron import CronParser
from logcrux.parsers.cups import CupsParser
from logcrux.parsers.dovecot import DovecotParser
from logcrux.parsers.etcd import EtcdParser
from logcrux.parsers.firewalld import FirewalldParser
from logcrux.parsers.generic import GenericParser
from logcrux.parsers.hashicorp import HashiCorpParser
from logcrux.parsers.journald import JournaldParser
from logcrux.parsers.keepalived import KeepalivedParser
from logcrux.parsers.kernel import KernelParser
from logcrux.parsers.mongodb import MongoDBParser
from logcrux.parsers.networkmanager import NetworkManagerParser
from logcrux.parsers.nginx_access import NginxAccessParser
from logcrux.parsers.nginx_error import NginxErrorParser
from logcrux.parsers.registry import detect_parser
from logcrux.parsers.slapd import SlapdParser
from logcrux.parsers.smartd import SmartdParser
from logcrux.parsers.squid import SquidParser
from logcrux.parsers.strongswan import StrongSwanParser
from logcrux.parsers.sudo import SudoParser
from logcrux.parsers.supervisor import SupervisorParser
from logcrux.parsers.syslog import SyslogParser
from logcrux.parsers.traefik import TraefikParser
from logcrux.parsers.zookeeper import ZookeeperParser


def test_detect_syslog_by_path():
    sample = ["Jun 16 03:42:00 host kernel: OOM killer fired"]
    parser = detect_parser(Path("/var/log/messages"), sample)
    assert isinstance(parser, SyslogParser)


def test_detect_journald_by_content():
    sample = ['{"PRIORITY":"3","MESSAGE":"test"}']
    parser = detect_parser(None, sample)
    assert isinstance(parser, JournaldParser)


def test_detect_nginx_error_by_content():
    sample = ["2026/06/16 03:41:00 [error] 456#456: connect() failed"]
    parser = detect_parser(None, sample)
    assert isinstance(parser, NginxErrorParser)


def test_format_override():
    parser = detect_parser(None, [], format_override="generic")
    assert isinstance(parser, GenericParser)


def test_unknown_format_override_raises():
    with pytest.raises(ValueError, match="Unknown format"):
        detect_parser(None, [], format_override="nonexistent")


def test_unknown_format_suggests_close_match():
    with pytest.raises(ValueError, match="Did you mean"):
        detect_parser(None, [], format_override="ngink")


def test_format_aliases():
    # The names users actually type (and the README examples) must work.
    assert detect_parser(None, [], format_override="nginx").FORMAT_NAME == "nginx-access"
    assert detect_parser(None, [], format_override="apache").FORMAT_NAME == "apache-access"
    assert detect_parser(None, [], format_override="k8s").FORMAT_NAME == "kubernetes"
    assert detect_parser(None, [], format_override="dmesg").FORMAT_NAME == "kernel"


def test_squid_clf_not_misdetected_as_nginx():
    # Squid CLF logs absolute URLs (forward proxy); must beat the web-access
    # parser whose CLF pattern would otherwise grab the same shape.
    line = '10.0.1.10 - - [16/Jun/2026:10:00:00 +0000] "GET http://example.com/ HTTP/1.1" 200 1234'
    parser = detect_parser(None, [line])
    assert isinstance(parser, SquidParser)


def test_nginx_access_still_detected_for_path_requests():
    line = '10.0.1.50 - - [16/Jun/2026:03:41:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "ua"'
    parser = detect_parser(None, [line])
    assert isinstance(parser, NginxAccessParser)


def test_generic_fallback_for_unrecognized():
    parser = detect_parser(None, ["this is just some random text"])
    assert isinstance(parser, GenericParser)


def test_detect_auditd_by_content():
    line = 'type=USER_AUTH msg=audit(1716113702.001:457): acct="root" res=failed'
    parser = detect_parser(None, [line])
    assert isinstance(parser, AuditdParser)


def test_detect_dmesg_by_content():
    parser = detect_parser(None, ["[ 300.770000] Out of memory: Killed process 9876 (mysqld)"])
    assert isinstance(parser, KernelParser)


def test_detect_dedicated_cron_log():
    sample = [
        "May 19 10:15:01 web01 CROND[12345]: (root) CMD (run-parts /etc/cron.hourly)",
        "May 19 10:17:01 web01 CROND[12350]: (root) CMD (cd / && run-parts /etc/cron.hourly)",
    ]
    parser = detect_parser(Path("/var/log/cron"), sample)
    assert isinstance(parser, CronParser)


def test_detect_dovecot_by_content():
    sample = ["May 19 10:15:01 mail01 dovecot: imap-login: Login: user=<alice>, rip=10.0.0.5"]
    parser = detect_parser(None, sample)
    assert isinstance(parser, DovecotParser)


def test_mixed_syslog_not_hijacked_by_service_tag():
    # A lone CROND line among generic syslog lines must NOT divert the whole
    # file to the per-service parser — it stays on the generic SyslogParser.
    sample = [
        "May 19 10:15:00 host systemd[1]: Started Daily apt upgrade.",
        "May 19 10:15:01 host CROND[12345]: (root) CMD (run-parts /etc/cron.hourly)",
        "May 19 10:15:02 host systemd[1]: Finished Daily apt upgrade.",
        "May 19 10:15:03 host dbus-daemon[789]: Activating service name='org.x'",
        "May 19 10:15:04 host systemd[1]: Reloading.",
    ]
    parser = detect_parser(None, sample)
    assert not isinstance(parser, CronParser)
    assert isinstance(parser, SyslogParser)


def test_single_tag_in_three_lines_not_dominant():
    # Regression: with 3 syslog lines, integer floor (3 // 2 == 1) let a single
    # tagged line count as "dominant", hijacking a mixed syslog and silently
    # dropping the other two-thirds. One of three is a minority — stay generic.
    sample = [
        "Jun 20 10:00:01 host systemd[1]: Started Daily apt.",
        "Jun 20 10:00:02 host CRON[123]: pam_unix(cron:session): session opened",
        "Jun 20 10:00:03 host systemd[1]: Finished Daily apt.",
    ]
    parser = detect_parser(None, sample)
    assert not isinstance(parser, CronParser)
    assert isinstance(parser, SyslogParser)


def test_exact_half_tag_is_dominant():
    # A dedicated service log may carry exactly half non-matching framing lines;
    # an exact half still counts as dominant (tagged * 2 >= len).
    sample = [
        "May 19 10:15:01 host CROND[1]: (root) CMD (run-parts /etc/cron.hourly)",
        "May 19 10:15:02 host CROND[2]: (root) CMD (run-parts /etc/cron.daily)",
    ]
    parser = detect_parser(None, sample)
    assert isinstance(parser, CronParser)


def test_sudo_does_not_shadow_secure_sshd_log():
    # An sshd auth log with an occasional sudo line stays with SecureParser.
    from logcrux.parsers.secure import SecureParser

    sample = [
        "May 19 10:15:00 host sshd[111]: Failed password for root from 1.2.3.4 port 22 ssh2",
        "May 19 10:15:01 host sshd[112]: Failed password for admin from 5.6.7.8 port 22 ssh2",
        "May 19 10:15:02 host sshd[113]: Accepted publickey for deploy from 10.0.0.5 port 22 ssh2",
        "May 19 10:15:03 host sudo:    deploy : TTY=pts/0 ; USER=root ; COMMAND=/bin/systemctl restart app",
    ]
    parser = detect_parser(None, sample)
    assert isinstance(parser, SecureParser)


def test_dedicated_sudo_log_detected():
    sample = [
        "May 19 10:15:01 host sudo:    alice : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/apt update",
        "May 19 10:15:02 host sudo:    bob : 3 incorrect password attempts ; USER=root ; COMMAND=/bin/su",
    ]
    parser = detect_parser(None, sample)
    assert isinstance(parser, SudoParser)


# ---------------------------------------------------------------------------
# Detection precision for the parsers added in this round. Each must claim its
# own format and stay out of a neighbour's lane (especially the JSON-per-line
# trio etcd/caddy/traefik vs MongoDB, and the syslog-tagged services).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "sample,expected",
    [
        (['{"level":"info","ts":"2026-06-20T10:23:45.123Z","caller":"a/b.go:1","msg":"x"}'], EtcdParser),
        (['{"level":"info","ts":1718880225.1,"logger":"http.log","msg":"x"}'], CaddyParser),
        (['{"level":"error","msg":"x","time":"2026-06-20T10:23:45Z"}'], TraefikParser),
        (['{"t":{"$date":"2024-06-20T10:23:45.123+00:00"},"s":"I","msg":"x"}'], MongoDBParser),
        (["[INFO] plugin/reload: Running configuration MD5 = abc"], CoreDNSParser),
        (["2026-06-20T10:23:45.123Z [INFO]  agent: Started Consul agent"], HashiCorpParser),
        (["2026-06-20 10:23:45,123 [myid:1] - INFO  [main:Foo@1] - hi"], ZookeeperParser),
        (["2026-06-20 10:23:45,123 INFO spawned: 'web' with pid 1234"], SupervisorParser),
        (["[2026-06-20 10:23:45,123: INFO/MainProcess] ready"], CeleryParser),
        (["I [20/Jun/2026:10:23:45 +0000] Listening to 127.0.0.1:631"], CupsParser),
    ],
)
def test_structured_parsers_detected_by_content(sample, expected):
    assert isinstance(detect_parser(None, sample), expected)


@pytest.mark.parametrize(
    "tag_line,expected",
    [
        ("Jun 20 10:23:45 h slapd[1]: conn=1 op=0 RESULT tag=97 err=49 text=", SlapdParser),
        ("Jun 20 10:23:45 h NetworkManager[1]: <warn>  [1.2] dhcp4 (eth0): timed out", NetworkManagerParser),
        ("Jun 20 10:23:45 h firewalld[1]: ERROR: COMMAND_FAILED: x", FirewalldParser),
        ("Jun 20 10:23:45 h Keepalived_vrrp[1]: VRRP_Instance(VI_1) Entering MASTER STATE", KeepalivedParser),
        ("Jun 20 10:23:45 h charon[1]: 09[IKE] establishing IKE_SA failed", StrongSwanParser),
        ("Jun 20 10:23:45 h smartd[1]: Device: /dev/sda [SAT], FAILED SMART self-check", SmartdParser),
    ],
)
def test_syslog_tagged_parsers_detected_when_dominant(tag_line, expected):
    assert isinstance(detect_parser(None, [tag_line, tag_line]), expected)


def test_lone_service_tag_does_not_hijack_mixed_syslog():
    # A mixed /var/log/syslog with a single slapd/NM line must fall through to
    # the generic syslog parser, not be claimed by the per-service parser.
    sample = [
        "Jun 20 10:23:45 h systemd[1]: Started Daily apt upgrade.",
        "Jun 20 10:23:46 h CRON[1]: (root) CMD (run-parts /etc/cron.hourly)",
        "Jun 20 10:23:47 h slapd[1]: conn=1 op=0 RESULT tag=97 err=0 text=",
        "Jun 20 10:23:48 h kernel: [123.4] usb 1-1: new device",
        "Jun 20 10:23:49 h systemd[1]: Reached target Timers.",
    ]
    parser = detect_parser(None, sample)
    assert isinstance(parser, SyslogParser)


_CLF_LINE = (
    '10.0.1.50 - - [16/Jun/2026:03:41:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
)


def test_apache_access_detected_for_apache_path():
    # Regression: NginxAccessParser was registered first and claimed apache paths
    # via content-based CLF detection before ApacheAccessParser could path-check.
    parser = detect_parser(Path("/var/log/apache2/access.log"), [_CLF_LINE])
    assert isinstance(parser, ApacheAccessParser), (
        f"Expected ApacheAccessParser, got {type(parser).__name__}. "
        "nginx parser must not claim apache paths via content detection."
    )


def test_nginx_access_detected_for_nginx_path():
    parser = detect_parser(Path("/var/log/nginx/access.log"), [_CLF_LINE])
    assert isinstance(parser, NginxAccessParser)


def test_nginx_access_claimed_by_content_when_no_path():
    # With no path context, the CLF format defaults to nginx-access (nginx is
    # listed first and content detection is ambiguous for this shared format).
    parser = detect_parser(None, [_CLF_LINE])
    assert isinstance(parser, NginxAccessParser)


def test_kernel_log_with_stray_apparmor_line_stays_kernel():
    # Regression: a kern.log with ONE AppArmor denial among ordinary kernel
    # lines was hijacked by the apparmor parser (presence-gated, not
    # dominance-gated), which parses only the denial and drops everything else.
    sample = [
        "May 19 10:14:55 web01 kernel: [12340.111000] usb 1-1: new high-speed USB device",
        "May 19 10:15:00 web01 kernel: [12345.678901] EXT4-fs (sda1): mounted filesystem",
        "May 19 10:15:30 web01 kernel: [12375.990000] audit: type=1400 "
        'audit(1716113730.1:99): apparmor="DENIED" operation="open"',
        "May 19 10:15:31 web01 kernel: [12376.000000] TCP: request_sock_TCP: SYN flooding",
    ]
    from logcrux.parsers.apparmor import AppArmorParser
    from logcrux.parsers.kernel import KernelParser

    parser = detect_parser(None, sample)
    assert not isinstance(parser, AppArmorParser)
    assert isinstance(parser, KernelParser)


def test_dedicated_apparmor_log_still_detected():
    sample = [
        'May 19 10:15:30 host kernel: audit: type=1400 audit(1716113730.1:99): '
        'apparmor="DENIED" operation="open" profile="/usr/sbin/mysqld"',
        'May 19 10:15:31 host kernel: audit: type=1400 audit(1716113731.2:100): '
        'apparmor="DENIED" operation="exec" profile="/usr/bin/man"',
    ]
    from logcrux.parsers.apparmor import AppArmorParser

    parser = detect_parser(None, sample)
    assert isinstance(parser, AppArmorParser)


def test_cloudwatch_agent_log_not_hijacked_by_telegraf():
    # Regression: the CloudWatch agent shares Telegraf's "ts L! [component]"
    # layout AND uses [outputs.cloudwatchlogs], which matched Telegraf's
    # component gate — telegraf (earlier in the registry) grabbed the file.
    sample = [
        "2026-06-23T10:23:45Z I! Starting AmazonCloudWatchAgent CWAgent/1.300",
        "2026-06-23T10:23:46Z W! [outputs.cloudwatchlogs] queue is full, dropping log entries",
        "2026-06-23T10:23:47Z E! [outputs.cloudwatchlogs] Aborted batch of 100 logs",
    ]
    from logcrux.parsers.cloudwatch import CloudWatchParser
    from logcrux.parsers.telegraf import TelegrafParser

    parser = detect_parser(None, sample)
    assert not isinstance(parser, TelegrafParser)
    assert isinstance(parser, CloudWatchParser)


def test_telegraf_still_detected():
    sample = [
        "2026-06-28T10:15:01Z I! Loaded inputs: cpu mem disk net",
        "2026-06-28T10:15:02Z W! [inputs.docker] Error gathering: connection refused",
        "2026-06-28T10:15:03Z E! [agent] Error writing to outputs.influxdb: timeout",
    ]
    from logcrux.parsers.telegraf import TelegrafParser

    parser = detect_parser(None, sample)
    assert isinstance(parser, TelegrafParser)
