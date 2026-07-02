/*
 * Copyright 2024-2026 Firefly Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.fireflyframework.security.method;

import org.fireflyframework.security.api.annotation.Secure;
import org.springframework.aop.Pointcut;
import org.springframework.aop.support.ComposablePointcut;
import org.springframework.aop.support.annotation.AnnotationMatchingPointcut;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Role;
import org.springframework.core.env.Environment;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeReactiveMethodInterceptor;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;

/**
 * Enables reactive method security ({@code @PreAuthorize}/{@code @PostAuthorize}) and registers the
 * {@link Secure} interceptor so {@code @Secure} works as ergonomic, fail-closed sugar on top of it.
 */
@AutoConfiguration
@EnableReactiveMethodSecurity
public class MethodSecurityAutoConfiguration {

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    public AuthorizationManagerBeforeReactiveMethodInterceptor fireflySecureMethodInterceptor(Environment environment) {
        Pointcut pointcut = new ComposablePointcut(new AnnotationMatchingPointcut(null, Secure.class, true))
                .union(new AnnotationMatchingPointcut(Secure.class, true));
        return new AuthorizationManagerBeforeReactiveMethodInterceptor(
                pointcut, new SecureMethodAuthorizationManager(environment::resolvePlaceholders));
    }
}
