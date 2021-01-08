package org.smart4j.plugin.security.aspect;

import org.smart4j.framework.annotation.Aspect;
import org.smart4j.framework.annotation.Controller;
import org.smart4j.framework.proxy.AspectProxy;
import org.smart4j.plugin.security.anootation.User;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;

/**
 * 授权注解切面
 */
@Aspect(Controller.class)
public class AuthzAnnotationAspect extends AspectProxy {

    /**
     * 授权功能的注解类数组
     */
    private static final Class[] ANNOTATION_CLASSES_ARRAY ={
            User.class
    };
    @Override
    public void before(Class<?> cls, Method method, Object[] params) throws Throwable {

    }

    private Annotation getAnnotation(Class<?> cls,Method method){
        //遍历全部的授权注解
        for (Class<? extends Annotation> annotationClass : ANNOTATION_CLASSES_ARRAY){
            //判断目标方法是否有对应的授权注解
            if(method.isAnnotationPresent(annotationClass)){
                return method.getAnnotation(annotationClass);
            }
            //判断目标类是否有带授权注解
            if(cls.isAnnotationPresent(annotationClass)){
                return cls.getAnnotation(annotationClass);
            }
        }
        //否则代表没有授权注解,返回null
        return null;
    }
}
