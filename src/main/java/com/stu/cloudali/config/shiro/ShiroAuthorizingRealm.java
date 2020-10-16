package com.stu.cloudali.config.shiro;

import org.apache.shiro.authc.*;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.crazycake.shiro.RedisCacheManager;
import org.crazycake.shiro.RedisManager;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class ShiroAuthorizingRealm extends AuthorizingRealm {


    /**
     * 授权（验证权限时调用）
     *
     * @param principalCollection
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        System.out.println("权限验证");
        //当我们使用 AuthorizingRealm 时，如果身份验证成功，在进行授权时就通过doGetAuthorizationInfo 方法获取角色/权限信息用于授权验证。
        // Shiro 提供了一个实现 SimpleAuthorizationInfo，大多数时候使用这个即可。
        List<String> rolesList = new ArrayList<>();
        rolesList.add("role1");
        rolesList.add("role2");
        rolesList.add("role3");

        List<String> perlist = new ArrayList<>();
        perlist.add("user:create");
        //perlist.add("user:update");
        perlist.add("user:login");
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        info.addRoles(rolesList);
        info.addStringPermissions(perlist);
        return info;
    }

    /**
     * 认证（登录时调用）
     *
     * @param authenticationToken
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        System.out.printf("身份验证登录验证");
        //得到用户名
        String username = (String)authenticationToken.getPrincipal();
        //得到密码
        String password = new String((char[])authenticationToken.getCredentials());
        password="123";
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
     * 配置自定义的权限登录器
     * CredentialsMatcher密码匹配对象
     *
     * @param matcher
     */
    @Bean(name = "authRealm")
    public ShiroAuthorizingRealm authRealm(@Qualifier("credentialsMatcher") CredentialsMatcher matcher) {
        System.out.println("进入 自定义权限匹配器");
        ShiroAuthorizingRealm authRealm = new ShiroAuthorizingRealm();
        authRealm.setCredentialsMatcher(matcher);
        authRealm.setCachingEnabled(true);
        //authRealm.setAuthenticationCachingEnabled(true);
        authRealm.setCacheManager(cacheManager());
        return authRealm;
    }


    /**
     * 配置自定义凭证匹配器
     *
     * @return
     */
    @Bean(name = "credentialsMatcher")
    public CredentialsMatcher credentialsMatcher() {
        System.out.println("进入 自定义凭证匹配器");
        return new CredentialsMatcher() {
            @Override
            public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
                UsernamePasswordToken utoken = (UsernamePasswordToken) token;
                // 获得用户输入的密码:(可以采用加盐(salt)的方式去检验)
                String inPassword = new String(utoken.getPassword());
                // 获得数据库中的密码
                String dbPassword = (String) info.getCredentials();
                // 进行密码的比对
                System.out.println("开始进行秘密对比");
                //return inPassword.equals(dbPassword);
                return true;
            }
        };
    }


    /**
     * 配置自定义缓存管理器
     */
    public RedisCacheManager cacheManager() {
        System.out.println("进入 自定义缓存管理器");
        RedisCacheManager redisCacheManager = new RedisCacheManager();
        redisCacheManager.setRedisManager(redisManager());
        return redisCacheManager;
    }


    /**
     * 配置redisManager
     */
    public RedisManager redisManager() {
        RedisManager redisManager = new RedisManager();
        redisManager.setHost("127.0.0.1:6379");
        redisManager.setTimeout(2000);    // 配置缓存过期时间
        redisManager.setTimeout(0);
        //redisManager.setPassword("1234");
        return redisManager;
    }


}
