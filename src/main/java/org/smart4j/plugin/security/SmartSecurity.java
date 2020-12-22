package org.smart4j.plugin.security;

import java.util.Set;

/**
 * Smart Security 接口
 * 可在应用中实现该接口，或者在smart.properties 文件中提供以下基于SQL的配置
 * smart.plugin.security.jdbc.authc_query 根据用户名获取密码
 * smart.plugin.security.jdbc.roles_query 根据用户名获取角色名集合
 * smart.plugin.security.jdbc.permissions_query 根据角色名获取权限名称集合
 */
public interface SmartSecurity {
    /**
     * 根据用户名获取密码
     *
     * @param username 用户名
     * @return
     */
    String getPassword(String username);

    /**
     * 根据用户名获取角色名集合
     *
     * @param username 用户名
     * @return
     */
    Set<String> getRoleNameSet(String username);

    /**
     * 根据角色名称获取权限名称集合
     *
     * @param roleName 角色名称
     * @return
     */
    Set<String> getPermissionNameSet(String roleName);
}
