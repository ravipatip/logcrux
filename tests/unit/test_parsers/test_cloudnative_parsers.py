"""Tests for the 20 cloud-native / Kubernetes / DevOps / cloud parsers:
klog, logrus, logfmt, envoy, cloudinit, cloudwatch, fluentbit, jenkins,
springboot, ansible, composelog, cloudtrail, gcp, gitlab, terraform, otel,
kubeaudit, vaultaudit, alb, vpcflow.

Each parser must (a) extract the right severity/message and (b) win detection
against the registry without poaching a neighbouring format.
"""
from __future__ import annotations

import pytest

from logcrux.models import Severity
from logcrux.parsers.alb import ALBParser
from logcrux.parsers.ansible import AnsibleParser
from logcrux.parsers.cloudinit import CloudInitParser
from logcrux.parsers.cloudtrail import CloudTrailParser
from logcrux.parsers.cloudwatch import CloudWatchParser
from logcrux.parsers.composelog import ComposeLogParser
from logcrux.parsers.envoy import EnvoyParser
from logcrux.parsers.fluentbit import FluentBitParser
from logcrux.parsers.gcp import GCPParser
from logcrux.parsers.gitlab import GitLabParser
from logcrux.parsers.jenkins import JenkinsParser
from logcrux.parsers.klog import KlogParser
from logcrux.parsers.kubeaudit import KubeAuditParser
from logcrux.parsers.logfmt import LogfmtParser
from logcrux.parsers.logrus import LogrusParser
from logcrux.parsers.otel import OtelParser
from logcrux.parsers.registry import detect_parser
from logcrux.parsers.springboot import SpringBootParser
from logcrux.parsers.terraform import TerraformParser
from logcrux.parsers.vaultaudit import VaultAuditParser
from logcrux.parsers.vpcflow import VPCFlowParser


# --------------------------------------------------------------------------- #
# klog (Kubernetes glog: kube-apiserver/kubelet/scheduler/controller-manager)
# --------------------------------------------------------------------------- #
def test_klog_levels_and_caller():
    p = KlogParser()
    info = p.parse_line("I0623 10:23:45.123456   12345 server.go:123] Starting", 1)
    assert info.severity == Severity.INFO
    assert info.extra["caller"] == "server.go:123"
    assert info.timestamp is not None and info.timestamp.month == 6
    err = p.parse_line("E0623 10:23:47.000000   12345 controller.go:310] failed to sync", 2)
    assert err.severity == Severity.ERROR
    assert p.parse_line("W0623 10:23:46.000000 1 r.go:1] watch ended", 3).severity == Severity.WARNING
    assert p.parse_line("F0623 10:23:46.000000 1 r.go:1] fatal", 4).severity == Severity.CRITICAL
    assert p.parse_line("not a klog line", 5) is None


# --------------------------------------------------------------------------- #
# logrus (containerd / dockerd / calico / argo)
# --------------------------------------------------------------------------- #
def test_logrus_message_and_error_fold():
    p = LogrusParser()
    e = p.parse_line(
        'time="2026-06-23T10:23:47.4Z" level=error msg="failed to start" error="address already in use"',
        1,
    )
    assert e.severity == Severity.ERROR
    assert "failed to start" in e.message
    assert "address already in use" in e.message
    assert p.parse_line("plain text", 2) is None


# --------------------------------------------------------------------------- #
# logfmt (Prometheus / Loki / Grafana / Vector)
# --------------------------------------------------------------------------- #
def test_logfmt_level_ts_and_err():
    p = LogfmtParser()
    e = p.parse_line(
        'level=error ts=2026-06-23T10:23:47.4Z caller=notifier.go:528 msg="Error sending alerts" err="connection refused"',
        1,
    )
    assert e.severity == Severity.ERROR
    assert e.timestamp is not None
    assert "connection refused" in e.message
    assert e.extra["caller"] == "notifier.go:528"
    # A logrus line (leading time=") must not be claimed by logfmt.
    assert p.parse_line('time="2026-06-23T10:23:45Z" level=info msg="x"', 2) is None
    # A bare key=value line without a level is not logfmt.
    assert p.parse_line("a=1 b=2 c=3", 3) is None


# --------------------------------------------------------------------------- #
# envoy (Istio / Envoy access + app logs)
# --------------------------------------------------------------------------- #
def test_envoy_access_status_to_severity():
    p = EnvoyParser()
    ok = p.parse_line('[2026-06-23T10:23:45.123Z] "GET /a HTTP/1.1" 200 - 0 1 1 1 "-" "ua" "r" "h" "1.2.3.4:80"', 1)
    assert ok.severity == Severity.INFO
    err = p.parse_line('[2026-06-23T10:23:46.223Z] "POST /b HTTP/1.1" 503 UF 0 1 1 - "-" "ua" "r" "h" "1.2.3.4:80"', 2)
    assert err.severity == Severity.ERROR
    assert err.extra["response_flags"] == "UF"


def test_envoy_app_log():
    p = EnvoyParser()
    e = p.parse_line("[2026-06-23 10:23:48.423][14][warning][config] [source/server.cc:120] failed", 1)
    assert e.severity == Severity.WARNING
    assert e.extra["component"] == "config"


# --------------------------------------------------------------------------- #
# cloud-init / cloudwatch / fluentbit
# --------------------------------------------------------------------------- #
def test_cloudinit_warning():
    e = CloudInitParser().parse_line(
        "2026-06-23 10:23:47,323 - url_helper.py[WARNING]: Calling metadata failed", 1
    )
    assert e.severity == Severity.WARNING
    assert e.extra["module"] == "url_helper.py"
    assert e.timestamp is not None


def test_cloudwatch_letter_levels():
    p = CloudWatchParser()
    assert p.parse_line("2026-06-23T10:23:47Z E! [outputs] Aborted batch", 1).severity == Severity.ERROR
    assert p.parse_line("2026/06/23 10:23:45 I! starting", 2).severity == Severity.INFO
    assert p.parse_line("2026/06/23 10:23:45 I! starting", 2).timestamp is not None


def test_fluentbit_and_fluentd():
    p = FluentBitParser()
    e = p.parse_line("[2026/06/23 10:23:47] [error] [output:es:es.0] could not flush", 1)
    assert e.severity == Severity.ERROR
    assert e.timestamp is not None
    fd = p.parse_line("2026-06-23 10:23:45 +0000 [warn]: #0 buffer flush took too long", 2)
    assert fd.severity == Severity.WARNING


# --------------------------------------------------------------------------- #
# jenkins / springboot
# --------------------------------------------------------------------------- #
def test_jenkins_severe_is_error():
    p = JenkinsParser()
    e = p.parse_line("2026-06-23 10:23:48.423+0000 [id=88]   SEVERE  hudson.model.Run#execute: build failed", 1)
    assert e.severity == Severity.ERROR
    assert e.extra["thread_id"] == "88"
    assert "build failed" in e.message


def test_springboot_levels():
    p = SpringBootParser()
    e = p.parse_line(
        "2026-06-23 10:23:48.423 ERROR 12345 --- [http-nio-8080-exec-2] c.e.OrderService : boom", 1
    )
    assert e.severity == Severity.ERROR
    assert e.source == "c.e.OrderService"
    assert e.message == "boom"


# --------------------------------------------------------------------------- #
# ansible
# --------------------------------------------------------------------------- #
def test_ansible_fatal_and_recap():
    p = AnsibleParser()
    fatal = p.parse_line('fatal: [web02]: FAILED! => {"msg": "boom"}', 1)
    assert fatal.severity == Severity.ERROR
    assert fatal.extra["host"] == "web02"
    ok = p.parse_line("ok: [web01]", 2)
    assert ok.severity == Severity.INFO
    recap_bad = p.parse_line("web02 : ok=2 changed=1 unreachable=0 failed=1 skipped=0", 3)
    assert recap_bad.severity == Severity.ERROR
    recap_ok = p.parse_line("web01 : ok=3 changed=1 unreachable=0 failed=0 skipped=0", 4)
    assert recap_ok.severity == Severity.INFO


# --------------------------------------------------------------------------- #
# composelog
# --------------------------------------------------------------------------- #
def test_composelog_prefix_and_severity():
    p = ComposeLogParser()
    e = p.parse_line("db-1       | 2026-06-23 10:23:48 ERROR  could not connect to peer", 1)
    assert e.source == "db-1"
    assert e.severity == Severity.ERROR
    assert e.timestamp is not None
    benign = p.parse_line("web-1      | 10.0.0.1 - - [23/Jun/2026:10:23:45] \"GET / HTTP/1.1\" 200 12", 2)
    assert benign.severity == Severity.INFO


# --------------------------------------------------------------------------- #
# cloudtrail / kubeaudit / vaultaudit (security audit JSON)
# --------------------------------------------------------------------------- #
def test_cloudtrail_error_code_is_warning():
    p = CloudTrailParser()
    line = ('{"eventVersion":"1.08","eventTime":"2026-06-23T10:23:47Z",'
            '"eventSource":"iam.amazonaws.com","eventName":"DeleteUser","awsRegion":"us-east-1",'
            '"sourceIPAddress":"198.51.100.9","userIdentity":{"userName":"mallory"},'
            '"errorCode":"AccessDenied","errorMessage":"not authorized"}')
    e = p.parse_line(line, 1)
    assert e.severity == Severity.WARNING
    assert "AccessDenied" in e.message
    assert "mallory" in e.message
    assert e.extra["error_code"] == "AccessDenied"


def test_kubeaudit_forbidden_is_warning():
    p = KubeAuditParser()
    line = ('{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"Request",'
            '"stage":"ResponseComplete","requestURI":"/api/v1/secrets","verb":"list",'
            '"user":{"username":"system:anonymous"},"sourceIPs":["203.0.113.9"],'
            '"responseStatus":{"code":403},"requestReceivedTimestamp":"2026-06-23T10:23:46.223Z"}')
    e = p.parse_line(line, 1)
    assert e.severity == Severity.WARNING
    assert e.extra["response_code"] == 403
    assert "system:anonymous" in e.message


def test_vaultaudit_permission_denied():
    p = VaultAuditParser()
    line = ('{"time":"2026-06-23T10:23:47.3Z","type":"response","auth":{"policies":["default"]},'
            '"request":{"operation":"update","path":"secret/data/prod/key","remote_address":"203.0.113.4"},'
            '"error":"permission denied"}')
    e = p.parse_line(line, 1)
    assert e.severity == Severity.WARNING
    assert e.extra["operation"] == "update"
    assert "permission denied" in e.message


# --------------------------------------------------------------------------- #
# gcp / gitlab / terraform / otel (structured JSON)
# --------------------------------------------------------------------------- #
def test_gcp_severity_scale_and_payload():
    p = GCPParser()
    crit = p.parse_line(
        '{"severity":"CRITICAL","timestamp":"2026-06-23T10:23:48.4Z","logName":"x","resource":{"type":"cloud_run_revision"},"textPayload":"OOMKilled"}',
        1,
    )
    assert crit.severity == Severity.CRITICAL
    assert crit.source == "cloud_run_revision"
    err = p.parse_line(
        '{"severity":"ERROR","timestamp":"2026-06-23T10:23:47.3Z","logName":"x","jsonPayload":{"message":"db refused"}}',
        2,
    )
    assert err.severity == Severity.ERROR
    assert "db refused" in err.message


def test_gitlab_status_escalates_severity():
    p = GitLabParser()
    e = p.parse_line(
        '{"severity":"INFO","time":"2026-06-23T10:23:45Z","correlation_id":"a1","method":"GET","path":"/api","status":500}',
        1,
    )
    assert e.severity == Severity.ERROR  # 5xx overrides reported INFO
    assert "GET /api" in e.message


def test_terraform_diagnostic_detail():
    p = TerraformParser()
    line = ('{"@level":"error","@message":"Error: creating EC2 Instance",'
            '"@module":"terraform.ui","@timestamp":"2026-06-23T10:23:48.4Z",'
            '"diagnostic":{"detail":"insufficient capacity"}}')
    e = p.parse_line(line, 1)
    assert e.severity == Severity.ERROR
    assert "insufficient capacity" in e.message


def test_otel_kind_and_error():
    p = OtelParser()
    line = ('{"level":"error","ts":"2026-06-23T10:23:48.4Z","caller":"exporterhelper/q.go:1",'
            '"msg":"Exporting failed","kind":"exporter","name":"otlp","error":"connection refused"}')
    e = p.parse_line(line, 1)
    assert e.severity == Severity.ERROR
    assert e.extra["kind"] == "exporter"
    assert "connection refused" in e.message


# --------------------------------------------------------------------------- #
# alb / vpcflow (AWS positional logs)
# --------------------------------------------------------------------------- #
def test_alb_5xx_is_error():
    p = ALBParser()
    line = ('https 2026-06-23T10:23:47.3Z app/my-alb/0a 10.0.0.3:5 10.0.1.7:8080 '
            '0.001 0.060 0.001 503 503 100 50 "POST https://x:443/pay HTTP/1.1" "curl" ECDHE TLSv1.2 arn')
    e = p.parse_line(line, 1)
    assert e.severity == Severity.ERROR
    assert e.extra["elb_status_code"] == "503"


def test_vpcflow_reject_is_warning():
    p = VPCFlowParser()
    accept = p.parse_line(
        "2 123456789012 eni-1235b8 172.31.16.139 172.31.16.21 20641 22 6 20 4249 1718530010 1718530070 ACCEPT OK", 1
    )
    assert accept.severity == Severity.INFO
    reject = p.parse_line(
        "2 123456789012 eni-1235b8 203.0.113.12 172.31.16.139 49152 3389 6 1 40 1718530080 1718530140 REJECT OK", 2
    )
    assert reject.severity == Severity.WARNING
    assert reject.extra["action"] == "REJECT"
    # The header line is metadata, not an event.
    assert p.parse_line("version account-id interface-id srcaddr dstaddr", 3) is None


# --------------------------------------------------------------------------- #
# Registry-level detection precision for every new format.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "sample,fmt",
    [
        (["I0623 10:23:45.123456   12345 server.go:123] Starting"], "klog"),
        (['time="2026-06-23T10:23:45Z" level=info msg="starting containerd" revision=a'], "logrus"),
        (['level=info ts=2026-06-23T10:23:45Z caller=main.go:1 msg="Starting Prometheus"'], "logfmt"),
        (['[2026-06-23T10:23:45.123Z] "GET /a HTTP/1.1" 200 - 0 1 1 1 "-" "ua" "r" "h" "1.2.3.4:80"'], "envoy"),
        (["2026-06-23 10:23:45,123 - util.py[WARNING]: failed"], "cloudinit"),
        (["2026-06-23T10:23:45Z E! [outputs] aborted"], "cloudwatch"),
        (["[2026/06/23 10:23:45] [error] [output:es] could not flush"], "fluentbit"),
        (["2026-06-23 10:23:45.123+0000 [id=42]   SEVERE  hudson.X#y: failed"], "jenkins"),
        (["2026-06-23 10:23:45.123  INFO 12345 --- [main] c.e.App : Started"], "springboot"),
        (['{"eventVersion":"1.08","eventTime":"2026-06-23T10:23:45Z","eventSource":"s3.amazonaws.com","eventName":"GetObject"}'], "cloudtrail"),
        (['{"severity":"ERROR","timestamp":"2026-06-23T10:23:45Z","logName":"x","textPayload":"boom"}'], "gcp"),
        (['{"severity":"INFO","time":"2026-06-23T10:23:45Z","correlation_id":"a","method":"GET","path":"/x","status":200}'], "gitlab"),
        (['{"@level":"info","@message":"hi","@module":"terraform.ui","@timestamp":"2026-06-23T10:23:45Z"}'], "terraform"),
        (['{"level":"info","ts":"2026-06-23T10:23:45Z","caller":"a/b.go:1","msg":"ready","kind":"exporter","name":"otlp"}'], "otel"),
        (['{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"Metadata","stage":"x","verb":"get","requestReceivedTimestamp":"2026-06-23T10:23:45Z"}'], "kubeaudit"),
        (['{"time":"2026-06-23T10:23:45Z","type":"response","auth":{},"request":{"operation":"read","path":"secret/x"}}'], "vaultaudit"),
        (['https 2026-06-23T10:23:45.1Z app/my-alb/0a 10.0.0.1:5 10.0.1.5:8080 0.001 0.002 0.003 200 200 1 1 "GET https://x:443/ HTTP/1.1" "ua" - - arn'], "alb"),
        (["2 123456789012 eni-1235b8 172.31.16.139 172.31.16.21 20641 22 6 20 4249 1718530010 1718530070 ACCEPT OK"], "vpcflow"),
    ],
)
def test_new_formats_detected(sample, fmt):
    assert detect_parser(None, sample).FORMAT_NAME == fmt


def test_ansible_detected_with_majority():
    sample = [
        "TASK [Gathering Facts] ********",
        "ok: [web01]",
        'fatal: [web02]: FAILED! => {"msg": "boom"}',
    ]
    assert detect_parser(None, sample).FORMAT_NAME == "ansible"


def test_composelog_detected_with_majority():
    sample = [
        "web-1   | 10.0.0.1 - - [23/Jun/2026:10:23:45] \"GET / HTTP/1.1\" 200 12",
        "db-1    | 2026-06-23 10:23:47 ERROR could not connect",
        "worker-1 | started consumer",
    ]
    assert detect_parser(None, sample).FORMAT_NAME == "composelog"


# --------------------------------------------------------------------------- #
# Non-poaching: the zap-encoder collision (otel vs etcd) and JSON neighbours.
# --------------------------------------------------------------------------- #
def test_otel_does_not_steal_plain_etcd_zap():
    # An etcd zap line (no pipeline "kind") must still go to etcd, not otel.
    etcd = ['{"level":"info","ts":"2026-06-23T10:23:45Z","caller":"embed/serve.go:98","msg":"ready"}']
    assert detect_parser(None, etcd).FORMAT_NAME == "etcd"


def test_gcp_does_not_steal_mongodb():
    mongo = ['{"t":{"$date":"2024-06-20T10:23:45.123+00:00"},"s":"I","c":"NET","msg":"x"}']
    assert detect_parser(None, mongo).FORMAT_NAME == "mongodb"


def test_auditd_does_not_hijack_audit_named_json_logs():
    # Regression: auditd path-matched any name containing the substring "audit"
    # (kubeaudit, vaultaudit), sending structured JSON logs to the generic
    # fallback and silently degrading their parse. Detection must follow content.
    from pathlib import Path

    ka = ['{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"Metadata","stage":"x","verb":"get","requestReceivedTimestamp":"2026-06-23T10:23:45Z"}']
    va = ['{"time":"2026-06-23T10:23:45Z","type":"response","auth":{},"request":{"operation":"read","path":"secret/x"}}']
    assert detect_parser(Path("/var/log/kubeaudit.log"), ka).FORMAT_NAME == "kubeaudit"
    assert detect_parser(Path("/var/log/vaultaudit.log"), va).FORMAT_NAME == "vaultaudit"
    # The real auditd log (name starts with "audit", or under an audit/ dir)
    # must still be claimed by auditd.
    auditd_line = ['type=USER_AUTH msg=audit(1716113702.001:457): acct="root" res=failed']
    assert detect_parser(Path("/var/log/audit/audit.log"), auditd_line).FORMAT_NAME == "auditd"
    assert detect_parser(Path("/var/log/audit/audit.log.1"), auditd_line).FORMAT_NAME == "auditd"


def test_otel_does_not_hijack_collector_named_non_otel_json():
    # Regression: otel claimed any "*collector*"/"*otel*" path that merely had a
    # JSON line. A MongoDB log named metrics-collector.log must stay mongodb.
    from pathlib import Path

    mongo = ['{"t":{"$date":"2024-06-20T10:23:45.123+00:00"},"s":"I","c":"NET","msg":"x"}']
    assert detect_parser(Path("/var/log/metrics-collector.log"), mongo).FORMAT_NAME == "mongodb"
