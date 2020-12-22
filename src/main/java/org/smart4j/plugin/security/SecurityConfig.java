package org.smart4j.plugin.security;


import org.smart4j.framework.helper.ConfigHelper;
import org.smart4j.framework.util.ReflectionUtil;

public class SecurityConfig {

    public static String getRealms(){
        return ConfigHelper.getString(SecurityConstant.REALMS);
    }

    public static String getJdbcAuthcQuery() {
        return ConfigHelper.getString(SecurityConstant.JDBC_AUTHC_QUERY);
    }

    public static String getJdbcRolesQuery() {
        return ConfigHelper.getString(SecurityConstant.JDBC_ROLES_QUERY);
    }
    public static String getJdbcPermissionsQuery() {
        return ConfigHelper.getString(SecurityConstant.JDBC_PERMISSIONS_QUERY);
    }

    public static boolean getPermissionsLookupEnabled() {
        return ConfigHelper.getBoolean(SecurityConstant.PERMISSIONS_LOOKUP_ENABLE);
    }

    public static SmartSecurity getSmartSecurity() {
        String className = ConfigHelper.getString(SecurityConstant.SMART_SECURITY);
        return (SmartSecurity) ReflectionUtil.newInstance(className);
    }

    public static boolean isCache() {
        return ConfigHelper.getBoolean(SecurityConstant.CACHE);
    }
}
