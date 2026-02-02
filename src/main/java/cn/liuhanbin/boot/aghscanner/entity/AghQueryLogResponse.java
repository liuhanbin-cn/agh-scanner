package cn.liuhanbin.boot.aghscanner.entity;

import lombok.Data;
import java.util.List;

@Data
public class AghQueryLogResponse {
    // 对应 JSON 中的 "data" 字段
    private List<AghQueryLog> data;
    private String oldest;
}