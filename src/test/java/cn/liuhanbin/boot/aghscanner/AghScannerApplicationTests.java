package cn.liuhanbin.boot.aghscanner;

import cn.liuhanbin.boot.aghscanner.service.AdScannerService;
import jakarta.annotation.Resource;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Set;

@SpringBootTest
class AghScannerApplicationTests {

    @Resource
    private AdScannerService service;

    @Test
    void contextLoads() {

        Set<String> strings = service.analyzeLogs();
        System.out.println(strings);

    }

}
