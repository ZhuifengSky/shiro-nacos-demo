package com.stu.cloudali;

import com.stu.cloudali.config.shiro.MyRealm;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.crazycake.shiro.RedisCacheManager;
import org.crazycake.shiro.RedisManager;
import org.junit.Assert;
import org.junit.Test;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;


@Controller
public class LoginController {


    /**
     * 登录验证
     *
     * @param username
     * @param password
     * @return
     */
    @ResponseBody
    @PostMapping("/sys/login")
    public String login(String username, String password,boolean rememberMe) {

        try {
            Subject subject = SecurityUtils.getSubject();
            // 加密
            password = DigestUtils.sha1Hex(password);
            UsernamePasswordToken token = new UsernamePasswordToken(username, password);
            token.setRememberMe(rememberMe);
            subject.login(token);
        } catch (UnknownAccountException e) {
            return "未知用户";
        } catch (IncorrectCredentialsException e) {
            return "凭证异常";
        } catch (LockedAccountException e) {
            return "账号被锁";
        } catch (AuthenticationException e) {
            return "账户验证失败";
        }

        return "登录成功！！";
    }


    /**
     * 登录验证
     *
     * @param username
     * @param password
     * @return
     */
    @ResponseBody
    @GetMapping("/sys/user")
    @RequiresPermissions("user:dert")
    public String getUser(String username, String password) {

        return "成功访问！！";
    }



    /**
     * 登录页面
     *
     * @return
     */
    @GetMapping("/login")
    public String login() {
        return "login";
    }


    /**
     * 主页面
     *
     * @return
     */
    @GetMapping("/index")
    public String index() {
        return "/index";
    }

    /**
     * 403页面
     *
     * @return
     */
    @GetMapping("/403")
    public String hasNoQx() {
        return "/403";
    }


    /**
     * 跳转到登录页面
     *
     * @return
     */
    @GetMapping("/")
    public String root() {
        return "login";
    }

    @ResponseBody
    @GetMapping("/sys/login2")
    public void testIniMyRealm() {
        //1、创建SecurityManager，
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        // 2.使用自己定义的myRealm.
        MyRealm realm = new MyRealm();
        realm.setName("MyRealm");
        realm.setCacheManager(cacheManager());
        securityManager.setRealm(realm);
        SecurityUtils.setSecurityManager(securityManager);
        //3、得到Subject及创建用户名/密码身份验证Token（即用户身份/凭证）
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("zhang", "123");
        try {
            //4、登录，即身份验证
            subject.login(token);
        } catch (UnknownAccountException e) {
            System.out.printf("未知用户");
        } catch (IncorrectCredentialsException e) {
            System.out.printf("凭证异常");
        } catch (LockedAccountException e) {
            System.out.printf("账户被锁");
        } catch (AuthenticationException e) {
            System.out.printf("验证失败");
        }
        //断言用户已经登录
        Assert.assertEquals(true, subject.isAuthenticated());
        //6、退出
        //subject.logout();
    }


    /**
     * 配置自定义缓存管理器
     */
    public RedisCacheManager cacheManager() {
        System.out.println("进入 自定义缓存管理器");
        RedisManager redisManager = new RedisManager();
        redisManager.setHost("127.0.0.1:6379");
        redisManager.setTimeout(2000);    // 配置缓存过期时间
        redisManager.setTimeout(0);
        //redisManager.setPassword("1234");
        RedisCacheManager redisCacheManager = new RedisCacheManager();
        redisCacheManager.setRedisManager(redisManager);
        return redisCacheManager;
    }


    /**
     * 退出操作
     *
     * @return
     */
    @ResponseBody
    @GetMapping(value = "/logout")
    public String logout() {
        SecurityUtils.getSubject().logout();
        return "ok";
    }



    @Test
    public void testHelloworld() {
        //1、创建SecurityManager，
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        // 2.设置自定义realm.
        IniRealm realm = new IniRealm("classpath:shiro.ini");
        securityManager.setRealm(realm);
        SecurityUtils.setSecurityManager(securityManager);
        //3、得到Subject及创建用户名/密码身份验证Token（即用户身份/凭证）
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("zhang", "123");
        try {
        //4、登录，即身份验证
            subject.login(token);
        } catch (UnknownAccountException e) {
            System.out.printf("未知用户");
        } catch (IncorrectCredentialsException e) {
            System.out.printf("凭证异常");
        } catch (LockedAccountException e) {
            System.out.printf("账户被锁");
        } catch (AuthenticationException e) {
            System.out.printf("验证失败");
        }
        Assert.assertEquals(true, subject.isAuthenticated()); //断言用户已经登录
        //6、退出
        subject.logout();
    }


}
