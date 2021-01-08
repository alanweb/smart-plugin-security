package org.smart4j.plugin.security.tag;

import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.tags.PermissionTag;

/**
 * 判断用户是否拥有其中之一的权限(逗号隔开,表示“与”的关系)
 */
public class HasAnyPermissionsTag extends PermissionTag {

    private static final String PERMISSION_NAME_DELIMITER = ",";

    @Override
    protected boolean showTagBody(String permissionNames) {
        boolean hasAnyPermission = false;
        Subject subject = getSubject();
        if (subject != null) {
            for (String permission :
                    permissionNames.split(PERMISSION_NAME_DELIMITER)) {
                if (subject.isPermitted(permission)) {
                    hasAnyPermission = true;
                    break;
                }
            }
        }
        return hasAnyPermission;
    }
}
