package cn.liuhanbin.boot.aghscanner.entity;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class AghQueryLog {
    private Question question;
    private String reason; // 只有 "NotFilteredNotFound" 的才需要预检
    private String status;

    @Data
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Question {
        private String name;
    }
}

