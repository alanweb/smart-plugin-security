package org.smart4j.plugin.security.password;

import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.credential.CredentialsMatcher;
import org.smart4j.framework.util.CodecUtil;

/**
 * Md5 密码匹配器
 */
public class Md5CredentialsMatcher implements CredentialsMatcher {

    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        //从表单提交过来的密码、明文，尚未经过MD5加密
        String password = String.valueOf(((UsernamePasswordToken) token).getPassword());
        //获取数据库中存储的密码,已经进行MD5加密
        String encrypted = String.valueOf(info.getCredentials());
        return CodecUtil.md5(password).equals(encrypted);
    }
}
