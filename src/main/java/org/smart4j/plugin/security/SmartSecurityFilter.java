package org.smart4j.plugin.security;

import org.apache.shiro.cache.MemoryConstrainedCacheManager;
import org.apache.shiro.mgt.CachingSecurityManager;
import org.apache.shiro.mgt.RealmSecurityManager;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.web.mgt.WebSecurityManager;
import org.apache.shiro.web.servlet.ShiroFilter;
import org.smart4j.framework.helper.ConfigHelper;
import org.smart4j.framework.util.ArrayUtil;
import org.smart4j.framework.util.StringUtil;
import org.smart4j.plugin.security.realm.SmartCustomRealm;
import org.smart4j.plugin.security.realm.SmartJdbcRealm;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * 安全过滤器
 */
public class SmartSecurityFilter extends ShiroFilter {
    @Override
    public void init() throws Exception {
        super.init();
        WebSecurityManager webSecurityManager = super.getSecurityManager();
        //设置 Realms 可同时支持多个 Realm 并按照先后顺序用逗号分隔
        setRealm(webSecurityManager);
        //设置 Cache 减少数据库查询次数 降低 I/O 访问
        setCache(webSecurityManager);
    }

    private void setRealm(WebSecurityManager webSecurityManager) {
        //读取 smart.plugin.security.realms 配置项
        String securityRealms = SecurityConfig.getRealms();
        if(StringUtil.isNotEmpty(securityRealms)){
            //根据逗号拆分
            String[] securityRealmArray = securityRealms.split(",");
            if(ArrayUtil.isNotEmpty(securityRealmArray)){
                Set<Realm> realms = new LinkedHashSet<Realm>();
                for (String securityRealm: securityRealmArray){
                    if(securityRealm.equalsIgnoreCase(SecurityConstant.REALMS_JDBC)){
                        //添加基于 JDBC 的 Realm 需配置SQL查询语句
                        addJdbcRealm(realms);
                    } else if (securityRealm.equalsIgnoreCase(SecurityConstant.REALMS_CUSTOM)){
                        //添加基于定制化的 Realm 需实现 SmartSecurity 接口
                        addCustomRealm(realms);
                    }
                }
                RealmSecurityManager realmSecurityManager = (RealmSecurityManager) webSecurityManager;
                realmSecurityManager.setRealms(realms);
            }
        }
    }

    private static void addJdbcRealm(Set<Realm> realms) {
        //添加自己实现的基于 JDBC 的Realm
        SmartJdbcRealm smartJdbcRealm = new SmartJdbcRealm();
        realms.add(smartJdbcRealm);
    }

    private void addCustomRealm(Set<Realm> realms) {
        //读取 smart.plugin.security.custom.class 配置项
        SmartSecurity smartSecurity =  SecurityConfig.getSmartSecurity();
        //添加自己实现的 Realm
        SmartCustomRealm smartCustomRealm = new SmartCustomRealm(smartSecurity);
        realms.add(smartCustomRealm);
    }

    private void setCache(WebSecurityManager webSecurityManager) {
        //读取smart.plugin.security.cache 配置项
        if(SecurityConfig.isCache()){
            CachingSecurityManager cachingSecurityManager = (CachingSecurityManager) webSecurityManager;
            //使用基于内存的 CacheManager
            MemoryConstrainedCacheManager cacheManager = new MemoryConstrainedCacheManager();
            cachingSecurityManager.setCacheManager(cacheManager);
        }
    }

}
