package com.stu.cloudali.config.shiro;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.realm.text.IniRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.crazycake.shiro.RedisCacheManager;
import org.crazycake.shiro.RedisManager;
import org.junit.Assert;
import org.junit.Test;

/**
 * @author
 */
public class MyRealm extends AuthorizingRealm {


    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        return null;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        System.out.println("执行验证方法");
        //得到用户名
        String username = (String)authenticationToken.getPrincipal();
        //得到密码
        String password = new String((char[])authenticationToken.getCredentials());
        if(!"zhang".equals(username)) {
            throw new UnknownAccountException(); //如果用户名错误
        }
        if(!"123".equals(password)) {
            throw new IncorrectCredentialsException(); //如果密码错误
        }
        //如果身份认证验证成功，返回一个AuthenticationInfo实现；
        return new SimpleAuthenticationInfo(username, password, getName());
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


    @Test
    public void testMyRealm() {
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



    @Test
    public void testIniMyRealm() {
        //1、创建SecurityManager，
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        // 2.设置自定义realm.
        IniRealm realm = new IniRealm("classpath:shiro-realm.ini");
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
