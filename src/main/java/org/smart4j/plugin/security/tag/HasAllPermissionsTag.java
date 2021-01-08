package org.smart4j.plugin.security.tag;

import org.apache.shiro.authz.Permission;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.tags.PermissionTag;

import java.util.Arrays;

/**
 * 判断用户是否拥有其中全部的权限(逗号隔开,表示“与”的关系)
 */
public class HasAllPermissionsTag extends PermissionTag {

    private static final String PERMISSION_NAME_DELIMITER = ",";

    @Override
    protected boolean showTagBody(String permissionNames) {
        boolean hasAllPermission = true;
        Subject subject = getSubject();
        if (subject != null) {
            for (String permission :
                    permissionNames.split(PERMISSION_NAME_DELIMITER)) {
                if (!subject.isPermitted(permission)) {
                    hasAllPermission = false;
                    break;
                }
            }
        }
        return hasAllPermission;
    }
}
