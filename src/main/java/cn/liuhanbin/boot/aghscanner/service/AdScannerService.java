package cn.liuhanbin.boot.aghscanner.service;

import cn.liuhanbin.boot.aghscanner.entity.AghQueryLogResponse;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.stream.Collectors;

@Service
public class AdScannerService {

    @Value("${agh.url}")
    private String aghUrl;

    private final RestTemplate restTemplate;
    private final Executor executor; // 注入线程池

    // 构造注入线程池
    public AdScannerService(RestTemplate restTemplate, @Qualifier("adScannerExecutor") Executor executor) {
        this.restTemplate = restTemplate;
        this.executor = executor;
    }

    public Set<String> analyzeLogs() {
        try {
            long start = System.currentTimeMillis();
            
            // 1. 获取日志
            AghQueryLogResponse response = restTemplate.getForObject(aghUrl, AghQueryLogResponse.class);
            if (response == null || response.getData() == null) {
                return Collections.emptySet();
            }

            // 2. 提取所有未拦截的去重域名
            List<String> candidates = response.getData().stream()
                    .filter(log -> "NotFilteredNotFound".equals(log.getReason()))
                    .map(log -> log.getQuestion().getName())
                    .distinct()
                    .collect(Collectors.toList());

            System.out.println("扫描到待分析域名: " + candidates.size() + " 个");

            // --- 阶段一：快速文本检测 (直接在主线程跑) ---
            Set<String> blockedDomains = candidates.stream()
                    .filter(this::isSuspiciousText)
                    .collect(Collectors.toSet());

            // --- 阶段二：深度检测 (异步并发) ---
            // 筛选出没命中白名单/黑名单，但又有点可疑需要联网查的域名
            List<String> deepCheckCandidates = candidates.stream()
                    .filter(d -> !blockedDomains.contains(d)) // 排除已经确定的
                    .filter(this::needsDeepCheck) // 初筛是否值得联网查
                    .collect(Collectors.toList());

            if (!deepCheckCandidates.isEmpty()) {
                System.out.println("触发深度检测域名数: " + deepCheckCandidates.size() + " (并发执行中...)");

                // 使用 CompletableFuture 并发执行
                List<CompletableFuture<String>> futures = deepCheckCandidates.stream()
                        .map(domain -> CompletableFuture.supplyAsync(() -> {
                            // 在线程池中执行耗时操作
                            if (deepContentCheck(domain)) {
                                return domain;
                            }
                            return null;
                        }, executor))
                        .collect(Collectors.toList());

                // 等待所有任务完成并收集结果
                Set<String> deepBlocked = futures.stream()
                        .map(CompletableFuture::join) // 这一步会阻塞主线程直到所有子任务完成
                        .filter(Objects::nonNull)
                        .collect(Collectors.toSet());

                blockedDomains.addAll(deepBlocked);
            }

            // 3. 格式化输出
            Set<String> finalRules = blockedDomains.stream()
                    .map(domain -> "||" + domain + "^")
                    .collect(Collectors.toSet());

            System.out.println("分析耗时: " + (System.currentTimeMillis() - start) + "ms, 生成规则: " + finalRules.size() + " 条");
            return finalRules;

        } catch (Exception e) {
            System.err.println("分析任务异常: " + e.getMessage());
            e.printStackTrace();
            return Collections.emptySet();
        }
    }

    /**
     * 判断是否值得进行深度检测
     * 避免对显然正常的域名(如 baidu.com)发起无意义的 HTTP 请求
     */
    private boolean needsDeepCheck(String domain) {
        // 白名单
        if (domain.contains("apple.com") || domain.contains("microsoft.com") || domain.contains("synology")) {
            return false;
        }
        // 只查带敏感词的，或者超长的看起来像 DGA 的
        return domain.contains("api") || domain.contains("log") || domain.length() > 20;
    }

    // 保留原有的 isSuspiciousText 逻辑
    public boolean isSuspiciousText(String domain) {
        List<String> keywords = Arrays.asList("adserver", "telemetry", "analytics", "tracking", "log-upload");
        if (keywords.stream().anyMatch(domain::contains)) return true;
        if (domain.contains("analysis") && (domain.contains("xunlei") || domain.contains("qq.com"))) return true;
        String firstPart = domain.split("\\.")[0];
        return firstPart.length() > 12 && firstPart.matches("^[a-z0-9]+$");
    }

    // 保留原有的 deepContentCheck 逻辑
    private boolean deepContentCheck(String domain) {
        // ... (保持你之前的代码不变) ...
        HttpURLConnection connection = null;
        try {
            URL url = new URL("https://" + domain); // 默认尝试 HTTPS
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("HEAD");
            connection.setConnectTimeout(2000); // 2秒超时
            connection.setReadTimeout(2000);

            String contentType = connection.getContentType();
            int length = connection.getContentLength();

            if (contentType != null && (contentType.contains("image/gif") || contentType.contains("image/png"))) {
                if (length > 0 && length < 100) {
                    System.out.println("[深度检测命中] 发现追踪像素: " + domain);
                    return true;
                }
            }
        } catch (Exception e) {
            // 连接失败很正常，忽略
        } finally {
            if (connection != null) connection.disconnect();
        }
        return false;
    }
}