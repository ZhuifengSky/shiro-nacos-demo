package com.stu.cloudali;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/config")
@RefreshScope
public class ConfigController {

    @Value("${user.name}")
    private String useName;

    @Value("${user.age}")
    private String age;

    @Value("${current.env}")
    private String currentEnv;



    @RequestMapping("/get")
    public String get() {
        return "当前环境: "+currentEnv+" 姓名:"+useName+" 年龄:"+age;
    }
}
