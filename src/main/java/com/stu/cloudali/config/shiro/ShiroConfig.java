package com.stu.cloudali.config.shiro;

import at.pollux.thymeleaf.shiro.dialect.ShiroDialect;
import org.apache.shiro.mgt.RememberMeManager;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.servlet.Cookie;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.crazycake.shiro.RedisCacheManager;
import org.crazycake.shiro.RedisManager;
import org.crazycake.shiro.RedisSessionDAO;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.LinkedHashMap;

@Configuration
public class ShiroConfig {

    /**
     *  配置安全事务管理器
     * @param authRealm
     * @return
     */
    @Bean(name = "securityManager")
    public SecurityManager securityManager(@Qualifier("authRealm") ShiroAuthorizingRealm authRealm) {
        System.err.println("--------------shiro已经加载----------------");
        DefaultWebSecurityManager manager = new DefaultWebSecurityManager();
        // 设置自定义realm.
        manager.setRealm(authRealm);
        //多个realms配置
//        ModularRealmAuthenticator s = new ModularRealmAuthenticator();
//        Collection<Realm> realms = new ArrayList<>();
//        realms.add(authRealm);
//        s.setRealms(realms);
//        manager.setAuthenticator(s);
        RememberMeManager rememberManager = cookieRememberMeManager();
        manager.setRememberMeManager(rememberManager);
        // 自定义缓存实现 使用redis
        manager.setCacheManager(cacheManager());
        // 自定义session管理 使用redis
        manager.setSessionManager(sessionManager());
        return manager;
    }


    /**
     * 过滤器及映射路径的配置
     *
     * @param manager
     */
    @Bean(name = "shiroFilter")
    public ShiroFilterFactoryBean shiroFilter(@Qualifier("securityManager") SecurityManager manager) {
        ShiroFilterFactoryBean bean = new ShiroFilterFactoryBean();
        bean.setSecurityManager(manager);
        // 配置登录的url和登录成功的url
        bean.setLoginUrl("/login");
        bean.setSuccessUrl("/index");
        // 配置访问权限,拦截器
        LinkedHashMap<String, String> filterChainDefinitionMap = new LinkedHashMap<>();
        // anon表示可以匿名访问  authc表示需要认证才可以访问
        filterChainDefinitionMap.put("/sys/login", "anon");
        filterChainDefinitionMap.put("/logout", "anon");
        filterChainDefinitionMap.put("/**", "authc");
        filterChainDefinitionMap.put("/403", "perms");


        // 未授权界面;
        bean.setUnauthorizedUrl("/403");
        bean.setFilterChainDefinitionMap(filterChainDefinitionMap);
        return bean;
    }


    /**
     * 配置shiro redisManager
     * 使用的是shiro-redis开源插件
     */
    public RedisManager redisManager() {
        System.out.println("进入 自定义缓存管理器");
        RedisManager redisManager = new RedisManager();
        redisManager.setHost("127.0.0.1:6379");
        //redisManager.setPassword("1234");
        redisManager.setTimeout(0);
        // redisManager.setPassword(password);
        return redisManager;
    }

    /**
     * 配置自定义缓存管理器
     */
    public RedisCacheManager cacheManager() {

        RedisCacheManager redisCacheManager = new RedisCacheManager();
        redisCacheManager.setRedisManager(redisManager());
        return redisCacheManager;
    }


    /**
     * RedisSessionDAO shiro sessionDao层的实现 通过redis
     * 使用的是shiro-redis
     */
    public RedisSessionDAO redisSessionDAO() {
        RedisSessionDAO redisSessionDAO = new RedisSessionDAO();
        redisSessionDAO.setRedisManager(redisManager());
        return redisSessionDAO;
    }



    /**
     * Session Manager
     * 使用的是shiro-redis开源插件
     *
     */
    @Bean
    public DefaultWebSessionManager sessionManager() {
        System.out.println("进入 自定义session管理器");
        DefaultWebSessionManager sessionManager = new DefaultWebSessionManager();
        sessionManager.setSessionDAO(redisSessionDAO());
        return sessionManager;
    }


    /**
     * 记住我管理器
     * @return
     */
    @Bean
    public RememberMeManager cookieRememberMeManager() {
        System.out.println("进入 记住我");
        CookieRememberMeManager rememberMeManager = new CookieRememberMeManager();
        Cookie cookie = new SimpleCookie("myRememberMe");
        cookie.setHttpOnly(true);
        cookie.setMaxAge(86400);
        rememberMeManager.setCookie(cookie);
        return rememberMeManager;
    }


    //启用shiro注解
    /*<!-- 保证实现了Shiro内部lifecycle函数的bean执行 -->
    <bean id="lifecycleBeanPostProcessor" class="org.apache.shiro.spring.LifecycleBeanPostProcessor"/>

    <bean class="org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator" depends-on="lifecycleBeanPostProcessor">
        <property name="proxyTargetClass" value="true" />
    </bean>

    <bean class="org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor">
        <property name="securityManager" ref="securityManager"/>
    </bean>*/

    /**
     * 为了支持Shiro的注释，按官方文档的介绍，在applicationContext.xml加两个bean定义：DefaultAdvisorAutoProxyCreator和AuthorizationAttributeSourceAdvisor
     *
     * @param manager
     */
    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(
            @Qualifier("securityManager") SecurityManager manager) {
        System.out.println("进入 启用注解");
        AuthorizationAttributeSourceAdvisor advisor = new AuthorizationAttributeSourceAdvisor();
        advisor.setSecurityManager(manager);
        return advisor;
    }
    /**
     * 为了支持Shiro的注释，按官方文档的介绍，在applicationContext.xml加两个bean定义：DefaultAdvisorAutoProxyCreator和AuthorizationAttributeSourceAdvisor
     *
     * @return
     */
    @Bean
    public DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator() {
        System.out.println("进入 自动代理创建");
        DefaultAdvisorAutoProxyCreator creator = new DefaultAdvisorAutoProxyCreator();
        creator.setProxyTargetClass(true);
        return creator;
    }

    /**
     * shiro管理生命周期的东西
     *
     * @return
     */
    @Bean
    public static LifecycleBeanPostProcessor lifecycleBeanPostProcessor() {
        System.out.println("进入 生命周期管理器");
        return new LifecycleBeanPostProcessor();
    }


    /**
     * springboot thymeleaf和shiro标签整合
     *
     * @return
     */
    @Bean
    public ShiroDialect shiroDialect() {
        return new ShiroDialect();
    }



}
