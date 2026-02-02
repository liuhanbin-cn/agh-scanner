package cn.liuhanbin.boot.aghscanner.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.concurrent.Executor;
import java.util.concurrent.ThreadPoolExecutor;

@Configuration
public class AsyncConfig {

    @Bean("adScannerExecutor")
    public Executor adScannerExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        // 核心线程数：根据你的群晖 CPU 核数设置，IO 密集型可以设大点，比如核数 * 2
        executor.setCorePoolSize(4);
        // 最大线程数：并发检测上限，设为 20 左右比较合适
        executor.setMaxPoolSize(20);
        // 队列大小：缓冲队列
        executor.setQueueCapacity(500);
        // 线程名称前缀，方便日志排查
        executor.setThreadNamePrefix("AdScan-");
        // 拒绝策略：如果队列满了，由调用者线程执行（这种策略最稳妥，不会丢任务）
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
        executor.initialize();
        return executor;
    }
}