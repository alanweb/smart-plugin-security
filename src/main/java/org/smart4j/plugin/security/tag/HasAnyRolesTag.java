package org.smart4j.plugin.security.tag;

import org.apache.shiro.subject.Subject;
import org.apache.shiro.web.tags.RoleTag;

import java.util.Arrays;

/**
 * 判断用户是否拥有其中一个或多个角色(逗号分隔,表示“或”的关系)
 */
public class HasAnyRolesTag extends RoleTag {
    private static final String ROLE_NAME_DELIMITER = ",";

    protected boolean showTagBody(String roleNames) {
        boolean hasAnyRole = false;
        final Subject subject = getSubject();
        for (String role : roleNames.split(ROLE_NAME_DELIMITER)) {
            if (subject.hasRole(role.trim())) {
                hasAnyRole = true;
                break;
            }
        }
        return hasAnyRole;
    }
}
