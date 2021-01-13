package org.smart4j.plugin.security.aspect;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.smart4j.framework.annotation.Aspect;
import org.smart4j.framework.annotation.Controller;
import org.smart4j.framework.proxy.AspectProxy;
import org.smart4j.plugin.security.anootation.User;
import org.smart4j.plugin.security.exception.AuthzException;
import org.smart4j.plugin.security.tag.HasAllPermissionsTag;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.Arrays;

/**
 * 授权注解切面
 */
@Aspect(Controller.class)
public class AuthzAnnotationAspect extends AspectProxy {

    /**
     * 授权功能的注解类数组
     */
    private static final Class[] ANNOTATION_CLASSES_ARRAY = {
            User.class,
            RequiresPermissions.class,
            RequiresRoles.class
    };

    @Override
    public void before(Class<?> cls, Method method, Object[] params) throws Throwable {
        //从目标类与目标方法中获取相应的注解
        Annotation annotation = getAnnotation(cls, method);
        if (annotation != null) {
            Class<? extends Annotation> annotationType = annotation.annotationType();
            if (annotationType.equals(User.class)) {
                handleUser();
            } else if (annotationType.equals(RequiresRoles.class)) {
                handleRoles(((RequiresRoles) annotation).value());
            } else if (annotationType.equals(RequiresPermissions.class)) {
                handlePermissions(((RequiresPermissions) annotation).value());
            }
        }
    }

    private void handleRoles(String[] value) throws AuthzException {
        Subject currentUser = SecurityUtils.getSubject();
        if (!currentUser.hasAllRoles(Arrays.asList(value))) {
            throw new AuthzException("当前用户缺少对应角色");
        }
    }

    private void handlePermissions(String[] value) throws AuthzException {
        Subject currentUser = SecurityUtils.getSubject();
        if (!HasAllPermissionsTag.hasAllPermission(currentUser, value)) {
            throw new AuthzException("当前用户缺少对应权限");
        }
    }

    private void handleUser() throws AuthzException {
        Subject currentUser = SecurityUtils.getSubject();
        PrincipalCollection principals = currentUser.getPrincipals();
        if (principals == null || principals.isEmpty())
            throw new AuthzException("当前用户没有登录");
    }

    private Annotation getAnnotation(Class<?> cls, Method method) {
        //遍历全部的授权注解
        for (Class<? extends Annotation> annotationClass : ANNOTATION_CLASSES_ARRAY) {
            //判断目标方法是否有对应的授权注解
            if (method.isAnnotationPresent(annotationClass)) {
                return method.getAnnotation(annotationClass);
            }
            //判断目标类是否有带授权注解
            if (cls.isAnnotationPresent(annotationClass)) {
                return cls.getAnnotation(annotationClass);
            }
        }
        //否则代表没有授权注解,返回null
        return null;
    }
}
