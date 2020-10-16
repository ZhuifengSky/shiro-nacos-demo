package com.stu.cloudali.config.shiro;

import org.apache.shiro.authc.*;
import org.apache.shiro.authc.pam.AbstractAuthenticationStrategy;
import org.apache.shiro.realm.Realm;

import java.util.Collection;

/**
 * 自定义认证策略
 * @author
 */
public class MyAuthenticationStrategy extends AbstractAuthenticationStrategy {

   @Override
   public AuthenticationInfo beforeAllAttempts(Collection<? extends Realm> var1, AuthenticationToken var2) throws AuthenticationException {
    AuthenticationInfo s = new SimpleAuthenticationInfo();
    //得到用户名
     String username = (String)var2.getPrincipal();
     //得到密码
     String password = new String((char[])var2.getCredentials());
     password="123";
     if(!"zhang".equals(username)) {
      throw new UnknownAccountException(); //如果用户名错误
     }
     if(!"123".equals(password)) {
      throw new IncorrectCredentialsException(); //如果密码错误
     }
     //如果身份认证验证成功，返回一个AuthenticationInfo实现；
     return new SimpleAuthenticationInfo(username, password,this.getClass().getName());
    }

    @Override
    public AuthenticationInfo beforeAttempt(Realm var1, AuthenticationToken var2, AuthenticationInfo var3) throws AuthenticationException{
     System.out.printf("attempt执行前");

     return var3;
    }

    @Override
    public AuthenticationInfo afterAttempt(Realm var1, AuthenticationToken var2, AuthenticationInfo var3, AuthenticationInfo var4, Throwable var5) throws AuthenticationException{
      System.out.printf("attempt执行后");
     return var3;
    }

    @Override
    public AuthenticationInfo afterAllAttempts(AuthenticationToken var1, AuthenticationInfo var2) throws AuthenticationException{
     System.out.printf("所有attempt执行后");

     return var2;
    }
}
