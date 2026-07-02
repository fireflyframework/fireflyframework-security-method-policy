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

import org.aopalliance.intercept.MethodInvocation;
import org.fireflyframework.security.api.annotation.Secure;
import org.fireflyframework.security.core.authz.SecureAuthorizationEvaluator;
import org.fireflyframework.security.core.authz.SecureRequirement;
import org.fireflyframework.security.webflux.authentication.PrincipalSupport;
import org.springframework.aop.support.AopUtils;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import reactor.core.publisher.Mono;

import java.lang.reflect.Method;
import java.util.function.UnaryOperator;

/**
 * Reactive {@link ReactiveAuthorizationManager} that enforces the {@link Secure} annotation on
 * methods (or their declaring class) using the framework's {@link SecureAuthorizationEvaluator}.
 * Fail-closed: an unauthenticated caller, or one that does not satisfy the requirement, is denied.
 *
 * <p>Declared roles/scopes/permissions are passed through a {@code valueResolver} (Spring property
 * placeholders when wired by the auto-config), so services can externalise per-product authority names,
 * e.g. {@code @Secure(roles = "${idp.security.admin-role:idp-admin}")}. Literal values are unaffected.</p>
 */
public class SecureMethodAuthorizationManager implements ReactiveAuthorizationManager<MethodInvocation> {

    private final SecureAuthorizationEvaluator evaluator = new SecureAuthorizationEvaluator();
    private final UnaryOperator<String> valueResolver;

    public SecureMethodAuthorizationManager() {
        this(UnaryOperator.identity());
    }

    public SecureMethodAuthorizationManager(UnaryOperator<String> valueResolver) {
        this.valueResolver = valueResolver == null ? UnaryOperator.identity() : valueResolver;
    }

    @Override
    public Mono<AuthorizationDecision> check(Mono<Authentication> authentication, MethodInvocation invocation) {
        Secure secure = resolve(invocation);
        if (secure == null) {
            return Mono.just(new AuthorizationDecision(true));
        }
        SecureRequirement requirement = SecureRequirement.from(secure, valueResolver);
        return authentication
                .filter(Authentication::isAuthenticated)
                .map(auth -> new AuthorizationDecision(
                        evaluator.evaluate(PrincipalSupport.extract(auth), requirement).granted()))
                .defaultIfEmpty(new AuthorizationDecision(false));
    }

    private Secure resolve(MethodInvocation invocation) {
        Method method = invocation.getMethod();
        Secure onMethod = AnnotatedElementUtils.findMergedAnnotation(method, Secure.class);
        if (onMethod != null) {
            return onMethod;
        }
        Class<?> targetClass = invocation.getThis() != null
                ? AopUtils.getTargetClass(invocation.getThis())
                : method.getDeclaringClass();
        return AnnotatedElementUtils.findMergedAnnotation(targetClass, Secure.class);
    }
}
