package cn.liuhanbin.boot.aghscanner.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.restclient.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestTemplate;

@Configuration
public class AghConfig {

    @Value("${agh.user}")
    private String user;

    @Value("${agh.pass}")
    private String pass;

    @Bean
    public RestTemplate restTemplate(RestTemplateBuilder builder) {

        return builder
                // 核心修复点 1：强制在第一次请求就发送认证头，不等待 401 挑战
                .basicAuthentication(user, pass)
                // 核心修复点 2：明确告诉服务器，我是 API 客户端，只要 JSON
                .defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE)
                .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .defaultHeader(HttpHeaders.USER_AGENT, "AdGuard-Scanner-Bot/1.0")
                .build();
    }
}