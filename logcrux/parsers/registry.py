from __future__ import annotations

from pathlib import Path

from logcrux.parsers.activemq import ActiveMQParser
from logcrux.parsers.airflow import AirflowParser
from logcrux.parsers.alb import ALBParser
from logcrux.parsers.ansible import AnsibleParser
from logcrux.parsers.apache_access import ApacheAccessParser
from logcrux.parsers.apache_error import ApacheErrorParser

# Batch 160 -> 200: storage / virtualization / big-data / app-server / framework /
# mail / network / Linux-daemon / agent formats.
from logcrux.parsers.apparmor import AppArmorParser
from logcrux.parsers.apthistory import AptHistoryParser
from logcrux.parsers.asterisk import AsteriskParser
from logcrux.parsers.auditd import AuditdParser
from logcrux.parsers.avahi import AvahiParser
from logcrux.parsers.azure import AzureParser
from logcrux.parsers.base import LogParser
from logcrux.parsers.bazel import BazelParser
from logcrux.parsers.bluetoothd import BluetoothdParser
from logcrux.parsers.bunyan import BunyanParser
from logcrux.parsers.caddy import CaddyParser
from logcrux.parsers.cassandra import CassandraParser
from logcrux.parsers.cef import CEFParser
from logcrux.parsers.celery import CeleryParser
from logcrux.parsers.ceph import CephParser
from logcrux.parsers.certbot import CertbotParser
from logcrux.parsers.chef import ChefParser
from logcrux.parsers.chrony import ChronyParser
from logcrux.parsers.ciscoasa import CiscoASAParser
from logcrux.parsers.clamav import ClamAVParser
from logcrux.parsers.clickhouse import ClickHouseParser
from logcrux.parsers.cloudflare import CloudflareParser
from logcrux.parsers.cloudfront import CloudFrontParser
from logcrux.parsers.cloudinit import CloudInitParser
from logcrux.parsers.cloudtrail import CloudTrailParser
from logcrux.parsers.cloudwatch import CloudWatchParser
from logcrux.parsers.cockroachdb import CockroachDBParser
from logcrux.parsers.composelog import ComposeLogParser
from logcrux.parsers.coredns import CoreDNSParser
from logcrux.parsers.cri import CRIParser
from logcrux.parsers.cron import CronParser
from logcrux.parsers.cups import CupsParser
from logcrux.parsers.datadog import DatadogParser
from logcrux.parsers.dbus import DBusParser
from logcrux.parsers.dhcpd import DhcpdParser
from logcrux.parsers.django import DjangoParser
from logcrux.parsers.dnsmasq import DnsmasqParser
from logcrux.parsers.docker import DockerParser
from logcrux.parsers.dovecot import DovecotParser
from logcrux.parsers.dpkg import DpkgParser
from logcrux.parsers.druid import DruidParser
from logcrux.parsers.elasticsearch import ElasticsearchParser
from logcrux.parsers.envoy import EnvoyParser
from logcrux.parsers.etcd import EtcdParser
from logcrux.parsers.exim import EximParser
from logcrux.parsers.fail2ban import Fail2BanParser
from logcrux.parsers.falco import FalcoParser
from logcrux.parsers.filebeat import FilebeatParser
from logcrux.parsers.firewalld import FirewalldParser
from logcrux.parsers.flink import FlinkParser
from logcrux.parsers.fluentbit import FluentBitParser
from logcrux.parsers.fortigate import FortiGateParser
from logcrux.parsers.freeradius import FreeRadiusParser
from logcrux.parsers.frr import FrrParser
from logcrux.parsers.ftp import FTPParser
from logcrux.parsers.gcp import GCPParser
from logcrux.parsers.gelf import GELFParser
from logcrux.parsers.generic import GenericParser
from logcrux.parsers.gitea import GiteaParser
from logcrux.parsers.githubactions import GitHubActionsParser
from logcrux.parsers.gitlab import GitLabParser
from logcrux.parsers.glusterfs import GlusterFSParser
from logcrux.parsers.gostdlib import GoStdlibParser
from logcrux.parsers.gradle import GradleParser
from logcrux.parsers.gunicorn import GunicornParser
from logcrux.parsers.hadoop import HadoopParser
from logcrux.parsers.haproxy import HAProxyParser
from logcrux.parsers.hashicorp import HashiCorpParser
from logcrux.parsers.hbase import HBaseParser
from logcrux.parsers.hive import HiveParser
from logcrux.parsers.iis import IISParser
from logcrux.parsers.jenkins import JenkinsParser
from logcrux.parsers.jetty import JettyParser
from logcrux.parsers.journald import JournaldParser
from logcrux.parsers.json_access import JsonAccessParser
from logcrux.parsers.jvmgc import JvmGcParser
from logcrux.parsers.kafka import KafkaParser
from logcrux.parsers.keepalived import KeepalivedParser
from logcrux.parsers.kernel import KernelParser
from logcrux.parsers.keycloak import KeycloakParser
from logcrux.parsers.kibana import KibanaParser
from logcrux.parsers.klog import KlogParser
from logcrux.parsers.klogjson import KlogJsonParser
from logcrux.parsers.kong import KongParser
from logcrux.parsers.krb5kdc import Krb5KdcParser
from logcrux.parsers.kubeaudit import KubeAuditParser
from logcrux.parsers.kubernetes import KubernetesParser
from logcrux.parsers.laravel import LaravelParser
from logcrux.parsers.leef import LEEFParser
from logcrux.parsers.libvirt import LibvirtParser
from logcrux.parsers.lighttpd import LighttpdParser
from logcrux.parsers.log4j import Log4jParser
from logcrux.parsers.logfmt import LogfmtParser
from logcrux.parsers.logrus import LogrusParser
from logcrux.parsers.logstash import LogstashParser
from logcrux.parsers.lxc import LxcParser
from logcrux.parsers.maven import MavenParser
from logcrux.parsers.mdadm import MdadmParser
from logcrux.parsers.mikrotik import MikroTikParser
from logcrux.parsers.minio import MinioParser
from logcrux.parsers.modsecurity import ModSecurityParser
from logcrux.parsers.mongodb import MongoDBParser
from logcrux.parsers.monit import MonitParser
from logcrux.parsers.mosquitto import MosquittoParser
from logcrux.parsers.mssql import MSSQLParser
from logcrux.parsers.mysql import MySQLParser
from logcrux.parsers.nagios import NagiosParser
from logcrux.parsers.named import NamedParser
from logcrux.parsers.nats import NatsParser
from logcrux.parsers.neo4j import Neo4jParser
from logcrux.parsers.networkmanager import NetworkManagerParser
from logcrux.parsers.nextcloud import NextcloudParser
from logcrux.parsers.nginx_access import NginxAccessParser
from logcrux.parsers.nginx_error import NginxErrorParser
from logcrux.parsers.npm import NpmParser
from logcrux.parsers.okta import OktaParser
from logcrux.parsers.opendkim import OpenDKIMParser
from logcrux.parsers.opensmtpd import OpenSMTPDParser
from logcrux.parsers.openvpn import OpenVPNParser
from logcrux.parsers.oracle import OracleParser
from logcrux.parsers.osquery import OsqueryParser
from logcrux.parsers.otel import OtelParser
from logcrux.parsers.otlp import OTLPParser
from logcrux.parsers.paloalto import PaloAltoParser
from logcrux.parsers.patroni import PatroniParser
from logcrux.parsers.pfsense import PfSenseParser
from logcrux.parsers.pgbouncer import PgBouncerParser
from logcrux.parsers.phoenix import PhoenixParser
from logcrux.parsers.phperror import PHPErrorParser
from logcrux.parsers.phpfpm import PhpFpmParser
from logcrux.parsers.pihole import PiholeParser
from logcrux.parsers.pingaccess import PingAccessParser
from logcrux.parsers.pingauthorize import PingAuthorizeParser
from logcrux.parsers.pingdirectory import PingDirectoryParser
from logcrux.parsers.pingfederate import PingFederateParser
from logcrux.parsers.pingintelligence import PingIntelligenceParser
from logcrux.parsers.pino import PinoParser
from logcrux.parsers.pip import PipParser
from logcrux.parsers.podman import PodmanParser
from logcrux.parsers.polkit import PolkitParser
from logcrux.parsers.postfix import PostfixParser
from logcrux.parsers.postgresql import PostgreSQLParser
from logcrux.parsers.powerdns import PowerDNSParser
from logcrux.parsers.pulsar import PulsarParser
from logcrux.parsers.puma import PumaParser
from logcrux.parsers.puppet import PuppetParser
from logcrux.parsers.pylogging import PyLoggingParser
from logcrux.parsers.qemu import QemuParser
from logcrux.parsers.rabbitmq import RabbitMQParser
from logcrux.parsers.rails import RailsParser
from logcrux.parsers.redis import RedisParser
from logcrux.parsers.rspamd import RspamdParser
from logcrux.parsers.rsyncd import RsyncdParser
from logcrux.parsers.rsyslog import RsyslogParser
from logcrux.parsers.s3access import S3AccessParser
from logcrux.parsers.saltstack import SaltStackParser
from logcrux.parsers.samba import SambaParser
from logcrux.parsers.secure import SecureParser
from logcrux.parsers.sendmail import SendmailParser
from logcrux.parsers.serilog import SerilogParser
from logcrux.parsers.sidekiq import SidekiqParser
from logcrux.parsers.slapd import SlapdParser
from logcrux.parsers.smartd import SmartdParser
from logcrux.parsers.snapd import SnapdParser
from logcrux.parsers.snort import SnortParser
from logcrux.parsers.solr import SolrParser
from logcrux.parsers.spamassassin import SpamAssassinParser
from logcrux.parsers.spark import SparkParser
from logcrux.parsers.springboot import SpringBootParser
from logcrux.parsers.squid import SquidParser
from logcrux.parsers.sssd import SssdParser
from logcrux.parsers.strongswan import StrongSwanParser
from logcrux.parsers.sudo import SudoParser
from logcrux.parsers.supervisor import SupervisorParser
from logcrux.parsers.suricata import SuricataParser
from logcrux.parsers.syslog import SyslogParser
from logcrux.parsers.syslogng import SyslogNgParser
from logcrux.parsers.tailscale import TailscaleParser
from logcrux.parsers.telegraf import TelegrafParser
from logcrux.parsers.terraform import TerraformParser
from logcrux.parsers.tomcat import TomcatParser
from logcrux.parsers.traefik import TraefikParser
from logcrux.parsers.trino import TrinoParser
from logcrux.parsers.ufw import UFWParser
from logcrux.parsers.unbound import UnboundParser
from logcrux.parsers.unifi import UnifiParser
from logcrux.parsers.uvicorn import UvicornParser
from logcrux.parsers.uwsgi import UwsgiParser
from logcrux.parsers.vaultaudit import VaultAuditParser
from logcrux.parsers.vmware import VMwareParser
from logcrux.parsers.vpcflow import VPCFlowParser
from logcrux.parsers.vsftpd import VsftpdParser
from logcrux.parsers.wazuh import WazuhParser
from logcrux.parsers.werkzeug import WerkzeugParser
from logcrux.parsers.wildfly import WildflyParser
from logcrux.parsers.winston import WinstonParser
from logcrux.parsers.wireguard import WireGuardParser
from logcrux.parsers.wpa_supplicant import WpaSupplicantParser
from logcrux.parsers.xorg import XorgParser
from logcrux.parsers.yum import YumParser
from logcrux.parsers.zabbix import ZabbixParser
from logcrux.parsers.zeek import ZeekParser
from logcrux.parsers.zfs import ZfsParser
from logcrux.parsers.zookeeper import ZookeeperParser

_PARSERS: list[type[LogParser]] = [
    # Path-specific parsers first (most precise detection)
    KubernetesParser,
    DockerParser,
    # CRI (containerd / CRI-O) container logs — the modern k8s node format at
    # /var/log/containers/*.log. Its "<RFC3339Nano> stdout|stderr F|P msg" shape
    # is highly distinctive, so content-based detection is safe even with no path
    # (e.g. piped `crictl logs` / `kubectl logs` output).
    CRIParser,
    JournaldParser,
    # Fluent Bit — its "[YYYY/MM/DD HH:MM:SS] [ info] [comp] msg" shape would
    # otherwise be claimed by the apache-error "[a] [b] msg" matcher, so it is
    # checked first. Its leading-bracket date keeps it clear of nginx-error.
    FluentBitParser,
    # Web servers (error logs have distinctive formats)
    NginxErrorParser,
    ApacheErrorParser,
    # Proxies / load balancers — checked before web-access parsers because a
    # proxy access log shares the CLF shape but logs absolute URLs / CONNECT.
    HAProxyParser,
    SquidParser,
    # Dev-server access logs (Flask/Werkzeug, Django runserver). Their bracket
    # date uses a *space* (no ":"+timezone), so they precede the CLF parsers to
    # claim their own shape but never poach a real combined/CLF access log.
    WerkzeugParser,
    DjangoParser,
    # JSON access logs (nginx `log_format json`) — strictly gated on a
    # "METHOD /path HTTP/x" request field + numeric status, so it claims only
    # real access JSON and never an app JSON logger. Precedes the CLF parsers.
    JsonAccessParser,
    # Web-server access logs (plain CLF / combined)
    NginxAccessParser,
    ApacheAccessParser,
    # AWS load-balancer / flow logs — fixed positional field layouts that share
    # nothing with the web-access CLF shape, but must precede the access parsers
    # so a quoted "request" field doesn't divert an ALB log to nginx/apache.
    ALBParser,
    VPCFlowParser,
    # AWS S3 server access log — 64-hex bucket-owner + "[date]" + REST.<op>.
    # positional layout; precedes the web-access CLF parsers so its quoted
    # request field doesn't divert it to nginx/apache.
    S3AccessParser,
    # Security / firewall / audit (auditd has a unique non-syslog record shape).
    # AppArmor MAC records carry a unique apparmor="DENIED" token and may arrive
    # with a kernel/auditd prefix, so they are claimed before auditd/kernel.
    AppArmorParser,
    AuditdParser,
    UFWParser,
    Fail2BanParser,
    # SIEM / firewall / IDS interchange + appliance formats. Each is keyed on a
    # distinctive marker (CEF:/LEEF: header, %ASA-<sev>- tag, Snort "[**] [sid]"
    # rule, Zeek "#fields" TSV, FortiGate date=+devid= key/values, Palo Alto CSV
    # log-type) so they win before the generic syslog / CSV catch-alls.
    CEFParser,
    LEEFParser,
    CiscoASAParser,
    SnortParser,
    ZeekParser,
    FortiGateParser,
    PaloAltoParser,
    # Per-service syslog-tagged parsers — must precede SecureParser/SyslogParser,
    # which match generically. Each only claims a log whose tag dominates the
    # sample (see syslog_tag_dominant), so mixed syslogs still fall through.
    SudoParser,
    CronParser,
    DhcpdParser,
    NamedParser,
    DovecotParser,
    SambaParser,
    ChronyParser,
    VsftpdParser,
    DnsmasqParser,
    PowerDNSParser,
    SlapdParser,
    NetworkManagerParser,
    FirewalldParser,
    # pfSense/OPNsense packet filter ("filterlog" tag, CSV payload).
    PfSenseParser,
    KeepalivedParser,
    StrongSwanParser,
    SmartdParser,
    # Additional per-service syslog-tagged daemons (mail / identity / VPN /
    # config-mgmt). Each is majority-gated via syslog_tag_dominant (or, for
    # krb5kdc/tailscale, keyed on a daemon-specific verb) so a stray tagged line
    # in a mixed /var/log/syslog can't divert the whole file.
    SendmailParser,
    OpenSMTPDParser,
    SssdParser,
    Krb5KdcParser,
    PuppetParser,
    TailscaleParser,
    # More per-service syslog-tagged daemons (storage / mail / routing / desktop
    # / system). Each is majority-gated via syslog_tag_dominant so a stray tagged
    # line in a mixed /var/log/syslog can't divert the whole file. SystemdParser
    # is the broadest tag, so it is checked after the specific ones; MikroTik is
    # keyed on RouterOS comma-joined topic groups rather than a program tag.
    ZfsParser,
    MdadmParser,
    SpamAssassinParser,
    OpenDKIMParser,
    FrrParser,
    DBusParser,
    PolkitParser,
    SnapdParser,
    BluetoothdParser,
    AvahiParser,
    SyslogNgParser,
    RsyslogParser,
    MikroTikParser,
    # Xorg server log: "[float] (II|WW|EE) msg". Shares the bracketed-uptime
    # shape with dmesg, so it precedes KernelParser; the (MM) marker keeps it
    # from poaching a real kernel log.
    XorgParser,
    KernelParser,
    SecureParser,
    # Structured application / middleware logs — each carries its own timestamp
    # format (not RFC3164 syslog) and a distinctive shape, so detection is
    # content-precise and order among them does not matter.
    # JSON-per-line parsers first; each can_parse keys off a distinctive field
    # so they don't poach one another or MongoDB's {"t":{"$date"...}} shape.
    # The cloud/k8s JSON parsers below key off unique top-level fields
    # (kubeaudit→apiVersion "audit.k8s.io", cloudtrail→eventSource+eventName,
    # vaultaudit→type+auth+request, terraform→"@level", gitlab→"time"+markers,
    # gcp→"severity"+"timestamp", otel→zap with pipeline "kind"). otel must
    # precede etcd because both use the zap encoder (caller+ts+msg+level); the
    # "kind" field disambiguates the collector.
    KubeAuditParser,
    CloudTrailParser,
    VaultAuditParser,
    TerraformParser,
    GitLabParser,
    GCPParser,
    AzureParser,
    # Other JSON-per-line loggers — each keys off a distinctive field set so it
    # cannot poach a neighbour: suricata→event_type, wazuh→rule.level+agent,
    # minio→errKind, modsecurity→transaction+audit_data, serilog→@t/@m,
    # bunyan→v:0, pino→numeric level+epoch time. Winston is the broadest
    # (string level+message+timestamp) so it is checked last among these.
    SuricataParser,
    WazuhParser,
    MinioParser,
    ModSecurityParser,
    # Nextcloud server log: JSON with the unique reqId + numeric level + app trio.
    NextcloudParser,
    # More JSON-per-line loggers, each keyed on a distinctive field set so it
    # cannot poach a neighbour: falco→priority+rule+output, osquery→
    # hostIdentifier+columns, okta→eventType+actor, cloudflare→RayID+
    # EdgeResponseStatus, kong→latencies+request+response.
    FalcoParser,
    OsqueryParser,
    OktaParser,
    CloudflareParser,
    KongParser,
    # PingAuthorize (formerly PingDataGovernance) policy-decision log — JSON with
    # an elapsedTime + a PERMIT/DENY/INDETERMINATE decision (top-level or nested
    # in results[]), a marker no other JSON logger emits.
    PingAuthorizeParser,
    SerilogParser,
    BunyanParser,
    PinoParser,
    # GELF (Graylog: version 1.1 + short_message) and Filebeat/Beats (ECS:
    # dotted "log.level" + "@timestamp") — keyed on fields Winston lacks, but
    # checked before the broad Winston matcher to be safe.
    GELFParser,
    FilebeatParser,
    WinstonParser,
    # OTLP (OpenTelemetry log records: body + severityNumber/severityText) and
    # klog structured JSON (--logging-format=json: ts+caller+msg+v/err, no level).
    # Both are keyed on fields the zap encoders (otel/etcd) lack, and conversely
    # require no "level", so they never collide with OtelParser/EtcdParser below.
    OTLPParser,
    KlogJsonParser,
    OtelParser,
    EtcdParser,
    CaddyParser,
    TraefikParser,
    MongoDBParser,
    # Logstash shares Elasticsearch's "[ts][LEVEL][logger]" shape, so it is
    # checked first and only claims a log whose logger is "logstash.*".
    LogstashParser,
    ElasticsearchParser,
    KafkaParser,
    RabbitMQParser,
    GunicornParser,
    PhpFpmParser,
    TomcatParser,
    ZookeeperParser,
    HashiCorpParser,
    CoreDNSParser,
    SupervisorParser,
    CeleryParser,
    CupsParser,
    EximParser,
    OpenVPNParser,
    # Structured app / IAM / database / HA formats with their own (non-syslog)
    # timestamped shapes, placed before the broad/log4j/syslog catch-alls:
    #   keycloak  ts LEVEL [org.keycloak…] (thread) msg  (precedes log4j)
    #   pulsar    ISO-ts [thread] LEVEL logger - msg      (precedes log4j)
    #   cassandra LEVEL [thread] ts File.java:line - msg
    #   activemq  ts | LEVEL | msg | logger | thread
    #   clickhouse  yyyy.mm.dd … <Level> src: msg
    #   mssql     ts.ff spidNN  msg     (precedes postgres/mysql)
    #   oracle    ISO-ts header + ORA-/TNS- error lines
    #   patroni   ts LEVEL: msg          (majority-gated)
    #   datadog   ts TZ | AGENT | LEVEL | (loc) | msg
    #   freeradius ctime : Category: msg
    #   wireguard ts peer(...) - msg
    # Ping Identity product family. Each owns a distinctive marker so it never
    # poaches a neighbour: PingFederate server.log has a unique "tid:" tracking
    # token (its pipe audit log requires field-2 to be a subject, not a level, so
    # it can't grab ActiveMQ's "ts | LEVEL | ..." shape — hence it precedes
    # ActiveMQ); PingAccess keys on a com.pingidentity logger or the " NN ms|"
    # audit round-trip field; PingDirectory (and PingDirectoryProxy/DataSync/
    # PingAuthorize) opens every line with a bracketed "[dd/Mon/yyyy:...]"
    # timestamp followed by category=/severity= or an LDAP operation keyword.
    PingFederateParser,
    PingAccessParser,
    PingDirectoryParser,
    # PingIntelligence API Security Enforcer (ASE) access/controller/balancer
    # logs: bracketed "[Www Mon DD HH:MM:SS:mmm YYYY] [thread:N] [level]" (the
    # colon-before-millis ctime is unique to ASE).
    PingIntelligenceParser,
    KeycloakParser,
    PulsarParser,
    CassandraParser,
    ActiveMQParser,
    ClickHouseParser,
    MSSQLParser,
    OracleParser,
    PatroniParser,
    DatadogParser,
    FreeRadiusParser,
    WireGuardParser,
    # Storage / virtualization / app-server / framework formats — each owns a
    # distinctive, non-syslog line shape so detection is content-precise:
    #   ceph       ts <hex-thread> <signed-prio> ... (vocab-gated)
    #   glusterfs  [ts] <L> [MSGID: n] [src] 0-vol: msg
    #   libvirt    ts+0000: pid: level : func:line : msg
    #   podman     ts +0000 UTC <type> <action> ...
    #   lxc        lxc <name> <14-digit-ts> LEVEL comp - src - msg
    #   qemu       [ts] qemu-system-<arch>: msg
    #   vmware     ts cpuN:world)[LEVEL:] msg
    #   pihole     [ts <pid><letter>] msg
    #   unifi      [ts] <thread> LEVEL  logger - msg
    #   laravel    [ts] env.LEVEL: msg
    #   phperror   [dd-Mon-yyyy HH:MM:SS TZ] PHP <Level>: msg (vocab-gated)
    #   puma       [pid] -/! msg (vocab-gated)
    #   kibana     log  [time] [level][tags] msg
    #   jetty      ts:LEVEL:oej*.logger:thread: msg (vocab-gated)
    #   wildfly    time LEVEL [org.jboss…] (thread) WFLY####: msg (vocab-gated)
    CephParser,
    GlusterFSParser,
    LibvirtParser,
    PodmanParser,
    LxcParser,
    QemuParser,
    VMwareParser,
    PiholeParser,
    UnifiParser,
    LaravelParser,
    PHPErrorParser,
    PumaParser,
    KibanaParser,
    JettyParser,
    WildflyParser,
    # rspamd spam filter — "ts #pid(worker) <tag>; module;" content shape.
    RspamdParser,
    # Cloud-native / k8s / DevOps text formats. Each matches a distinctive,
    # non-syslog line shape (klog glog letters, logrus time="...", Envoy access,
    # cloud-init, CloudWatch agent "I!", Fluent Bit brackets, Jenkins JUL,
    # Spring Boot/Logback) so detection is content-precise.
    # CockroachDB (crdb-v2) shares the glog letter+date prefix but carries a
    # unique "⋮" redaction marker + 6-digit YYMMDD date; checked before klog.
    CockroachDBParser,
    KlogParser,
    LogrusParser,
    EnvoyParser,
    CloudInitParser,
    # Telegraf shares the CloudWatch agent's "ts I!/W!/E!" marker, so it is
    # checked first and gated on a Telegraf [agent]/[inputs.…]/[outputs.…] tag.
    TelegrafParser,
    CloudWatchParser,
    JenkinsParser,
    SpringBootParser,
    # Databases
    MySQLParser,
    # PgBouncer ("LEVEL message", no colon) must precede PostgreSQL
    # ("LEVEL:  message") so the pooler log isn't read as the server's.
    PgBouncerParser,
    PostgreSQLParser,
    RedisParser,
    # Mail / FTP
    PostfixParser,
    FTPParser,
    # Broad structured formats — matched only on a clear majority of lines so a
    # stray line can't hijack a file. Placed last (before syslog/generic) so a
    # more specific parser always wins first:
    #   logfmt (Prometheus/Loki/Grafana/Vector: level=+msg=),
    #   ansible playbook output (PLAY/TASK/ok:/fatal:),
    #   docker-compose multiplexed "<service> | ..." streams.
    LogfmtParser,
    AnsibleParser,
    ComposeLogParser,
    # Additional application / server / package-manager / CI / security formats.
    # Distinctive line shapes are listed first; the broad majority-match ones
    # (pylogging, log4j, maven, mosquitto) carry their own >=50% guard so a
    # stray line can't hijack a file. All precede syslog/generic.
    GitHubActionsParser,
    UwsgiParser,
    UvicornParser,
    NatsParser,
    AsteriskParser,
    UnboundParser,
    NagiosParser,
    RailsParser,
    CloudFrontParser,
    IISParser,
    AptHistoryParser,
    DpkgParser,
    YumParser,
    # Distinctive application / orchestration / build / desktop formats. Each
    # owns a unique line shape (airflow {file:line}, sidekiq pid=/tid=, saltstack
    # [salt.*][LEVEL], certbot ts:LEVEL:module, monit [TZ date] level:, zabbix
    # PID:date:time, rsyncd [pid], lighttpd (file.c.NN), xorg (II/WW/EE),
    # wpa_supplicant CTRL-EVENT-, clamav " -> ", jvmgc [gc]). The Java log4j
    # family (hadoop/spark/neo4j/solr) is gated on a package/vocabulary marker so
    # it never poaches a generic log4j log. All precede pylogging/log4j/syslog.
    AirflowParser,
    SidekiqParser,
    SaltStackParser,
    CertbotParser,
    Neo4jParser,
    SolrParser,
    # HBase/Hive/Flink loggers can contain "org.apache.hadoop" or Hadoop vocab
    # ("ResourceManager"), which the Hadoop parser also keys on, so they are
    # checked before HadoopParser to avoid being poached. Each is vocabulary-gated
    # so none poaches a neighbour or the generic log4j. Trino uses the airlift
    # "ISO-ts LEVEL thread logger msg" layout instead of classic log4j.
    HBaseParser,
    HiveParser,
    FlinkParser,
    DruidParser,
    TrinoParser,
    HadoopParser,
    SparkParser,
    ChefParser,
    JvmGcParser,
    LighttpdParser,
    MonitParser,
    ZabbixParser,
    RsyncdParser,
    WpaSupplicantParser,
    ClamAVParser,
    PyLoggingParser,
    Log4jParser,
    MosquittoParser,
    MavenParser,
    # Build / CI / package-manager console output (untimestamped). Marker-gated
    # detection (Gradle "> Task"/BUILD banners, "npm <level>", Bazel level+a
    # Bazel-specific phrase, pip Collecting/Installed) keeps them clear of real
    # service logs while still never dropping a build-log line silently.
    GradleParser,
    NpmParser,
    BazelParser,
    PipParser,
    # Gitea ("src.go:line:func() [L]") precedes the broad, majority-gated Go
    # stdlib and Elixir/Phoenix loggers, both of which carry no service marker and
    # so are checked last (before syslog/generic) to avoid poaching.
    GiteaParser,
    GoStdlibParser,
    PhoenixParser,
    # System catch-alls
    SyslogParser,
    GenericParser,
]

_FORMAT_MAP: dict[str, type[LogParser]] = {
    cls.FORMAT_NAME: cls for cls in _PARSERS
}

# Convenience aliases for the names users actually type. Each maps to the
# format a user pointing at that kind of log almost always means (e.g. plain
# "nginx" is the access log; the error log has its own explicit name).
_FORMAT_ALIASES: dict[str, str] = {
    "nginx": "nginx-access",
    "apache": "apache-access",
    "k8s": "kubernetes",
    "dmesg": "kernel",
    "ssh": "secure",
    "auth": "secure",
    "dnf": "yum",
    "journal": "journald",
    # Ping Identity product names → the parser that handles that product's logs.
    # The Ping Data platform products share one server/access/error log format
    # (the pingdirectory parser); PingDataGovernance is PingAuthorize's old name.
    "pingdirectoryproxy": "pingdirectory",
    "pingdatasync": "pingdirectory",
    "pingdatametrics": "pingdirectory",
    "pingdatagovernance": "pingauthorize",
}


def detect_parser(
    path: Path | None,
    sample_lines: list[str],
    format_override: str | None = None,
) -> LogParser:
    if format_override is not None:
        format_override = _FORMAT_ALIASES.get(format_override, format_override)
        if format_override not in _FORMAT_MAP:
            import difflib

            close = difflib.get_close_matches(
                format_override, [*_FORMAT_MAP, *_FORMAT_ALIASES], n=3
            )
            hint = f" Did you mean: {', '.join(close)}?" if close else ""
            raise ValueError(
                f"Unknown format: {format_override!r}.{hint} "
                f"Valid: {', '.join(sorted(_FORMAT_MAP))}"
            )
        return _FORMAT_MAP[format_override]()
    # A format's shape is visible in a line's first few KB. Detection runs every
    # parser's can_parse regexes over the sample, and a single pathological line
    # (minified JSON, binary blob) can otherwise stall a backtracking regex for
    # minutes. Data lines themselves are not truncated — only what detection sees.
    sample_lines = [ln[:8192] for ln in sample_lines]
    for cls in _PARSERS:
        if cls.can_parse(path, sample_lines):
            return cls()
    raise RuntimeError("unreachable: GenericParser must always match")
