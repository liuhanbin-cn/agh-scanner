package cn.liuhanbin.boot.aghscanner.service;

import cn.liuhanbin.boot.aghscanner.entity.AghQueryLogResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

@Service
public class AdScannerService {

    @Value("${agh.url:http://192.168.1.100:3000/control/querylog?limit=30000}")
    private String aghUrl;

    private static final String RULE_FILE_PATH = "/volume1/web/autoblock.txt";

    // --- 配置常量 ---
    private static final int BLOCK_THRESHOLD = 60; // 拦截阈值
    private static final int DEEP_CHECK_TRIGGER_MIN = 30; // 触发深度检测的最低分
    private static final int DEEP_CHECK_TRIGGER_MAX = 59; // 触发深度检测的最高分

    // 1. 白名单 (大幅减分)
    private static final List<String> WHITELIST = Arrays.asList(
            "apple.com", "microsoft.com", "synology.com", "google.com", "amazon.com", "liuhanbin.cn"
    );
    // 2. CDN 白名单 (防止误杀长域名)
    private static final List<String> CDN_WHITELIST = Arrays.asList(
            "cloudfront.net", "akamaihd.net", "amazonaws.com", "cdn.jsdelivr.net",
            "aliyuncs.com", "myqcloud.com", "herokuapp.com", "azureedge.net"
    );
    // 3. 黑名单词库
    private static final List<String> BLACK_KEYWORDS = Arrays.asList(
            "adserver", "telemetry", "analytics", "tracking", "log-upload", "metrics", "stat"
    );

    private final RestTemplate restTemplate;
    private final ExecutorService executorService;

    public AdScannerService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
        this.executorService = Executors.newFixedThreadPool(10);
    }

    /**
     * 主流程：拉取 -> 智能打分 -> (可选深度检测) -> 拦截 -> 保存
     */
    public Set<String> analyzeAndSave() {
        Set<String> newRules = analyzeLogs();
        if (!newRules.isEmpty()) {
            saveRulesToFile(newRules);
        }
        return newRules;
    }

    public Set<String> analyzeLogs() {
        try {
            long start = System.currentTimeMillis();
            AghQueryLogResponse response = restTemplate.getForObject(aghUrl, AghQueryLogResponse.class);

            if (response == null || response.getData() == null) return Collections.emptySet();

            // 1. 提取去重域名
            List<String> candidates = response.getData().stream()
                    .filter(log -> "NotFilteredNotFound".equals(log.getReason()))
                    .map(log -> log.getQuestion().getName())
                    .distinct()
                    .collect(Collectors.toList());

            System.out.println("扫描到候选域名: " + candidates.size() + " 个");

            Set<String> finalBlockList = new HashSet<>();
            List<String> deepCheckCandidates = new ArrayList<>();

            // 2. 初步评分 (主线程快速执行)
            for (String domain : candidates) {
                int score = calculateStaticScore(domain);

                if (score >= BLOCK_THRESHOLD) {
                    // 分数够高，直接判死刑
                    finalBlockList.add(domain);
                } else if (score >= DEEP_CHECK_TRIGGER_MIN && score <= DEEP_CHECK_TRIGGER_MAX) {
                    // 分数不高不低 (疑似)，列入深度检测名单
                    deepCheckCandidates.add(domain);
                }
                // 分数太低直接放过
            }

            // 3. 深度检测 (异步并发)
            if (!deepCheckCandidates.isEmpty()) {
                System.out.println("触发深度检测域名数: " + deepCheckCandidates.size());

                List<CompletableFuture<String>> futures = deepCheckCandidates.stream()
                        .map(domain -> CompletableFuture.supplyAsync(() -> {
                            // 深度检测命中直接 +100 分，肯定超阈值
                            if (deepContentCheck(domain)) {
                                return domain;
                            }
                            return null;
                        }, executorService))
                        .toList();

                Set<String> confirmed = futures.stream()
                        .map(CompletableFuture::join)
                        .filter(Objects::nonNull)
                        .collect(Collectors.toSet());

                finalBlockList.addAll(confirmed);
            }

            System.out.println("分析耗时: " + (System.currentTimeMillis() - start) + "ms. 生成规则: " + finalBlockList.size() + " 条");
            return finalBlockList.stream().map(d -> "||" + d + "^").collect(Collectors.toSet());

        } catch (Exception e) {
            e.printStackTrace();
            return Collections.emptySet();
        }
    }

    /**
     * 核心算法：静态特征打分
     */
    private int calculateStaticScore(String domain) {
        int score = 0;

        // --- 减分项 (白名单) ---
        if (WHITELIST.stream().anyMatch(domain::contains)) score -= 100;
        if (CDN_WHITELIST.stream().anyMatch(domain::contains)) score -= 50;

        // --- 加分项 (特征匹配) ---

        // 1. 关键词命中 (+40分)
        if (BLACK_KEYWORDS.stream().anyMatch(domain::contains)) score += 40;

        // 2. 特定组合 (+60分，直接封杀)
        if (domain.contains("analysis") && (domain.contains("xunlei") || domain.contains("qq.com"))) score += 60;

        // 3. DGA (随机域名) 改进算法
        score += calculateDgaScore(domain);

        return score;
    }

    /**
     * 改进版 DGA 检测算法 (方案三)
     * 不只看长度，还看字符混乱度
     */
    private int calculateDgaScore(String domain) {
        String firstPart = domain.split("\\.")[0];
        int dgaScore = 0;

        // 特征 A: 长度异常 (+10 ~ +30)
        if (firstPart.length() > 12) dgaScore += 10;
        if (firstPart.length() > 20) dgaScore += 20;

        // 特征 B: 数字占比过高 (+20) -> 典型的机器生成特征
        long digitCount = firstPart.chars().filter(Character::isDigit).count();
        if (firstPart.length() > 0 && (double) digitCount / firstPart.length() > 0.3) {
            dgaScore += 20;
        }

        // 特征 C: 缺少元音 (+20) -> 看起来像乱码 (如 'bcdfgh')
        // 正常英文单词通常包含 a,e,i,o,u
        long vowelCount = firstPart.chars()
                .filter(c -> "aeiou".indexOf(c) != -1)
                .count();
        if (firstPart.length() > 5 && vowelCount == 0) {
            dgaScore += 20;
        }

        // 特征 D: 不包含连字符 (+10) -> 很多正常服务会用 api-server 这种格式
        if (!firstPart.contains("-") && firstPart.length() > 10) {
            dgaScore += 10;
        }

        return dgaScore;
    }

    /**
     * 深度检测 (方案二中的高权重验证)
     * 返回 true 代表实锤，直接拦截
     */
    private boolean deepContentCheck(String domain) {
        HttpURLConnection conn = null;
        try {
            URL url = new URL("https://" + domain);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("HEAD");
            conn.setConnectTimeout(1500);
            conn.setReadTimeout(1500);

            String type = conn.getContentType();
            int len = conn.getContentLength();

            // 命中追踪像素特征
            if (type != null && (type.contains("image/gif") || type.contains("image/png")) && len > 0 && len < 100) {
                System.out.println("[实锤] 发现追踪像素: " + domain);
                return true;
            }
        } catch (Exception e) {
            // 连接失败不扣分也不加分
        } finally {
            if (conn != null) conn.disconnect();
        }
        return false;
    }

    private void saveRulesToFile(Set<String> rules) {
        try {
            Path path = Paths.get(RULE_FILE_PATH);
            Set<String> allRules = Files.exists(path) ? new HashSet<>(Files.readAllLines(path)) : new HashSet<>();
            if (allRules.addAll(rules)) {
                Files.write(path, allRules, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
                System.out.println("规则文件已更新，当前总条数: " + allRules.size());
            }
        } catch (IOException e) {
            System.err.println("写入文件失败: " + e.getMessage());
        }
    }
}