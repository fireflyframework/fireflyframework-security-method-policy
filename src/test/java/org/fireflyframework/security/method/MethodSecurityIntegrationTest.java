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
import org.fireflyframework.security.api.domain.SecurityPrincipal;
import org.fireflyframework.security.webflux.authentication.FireflyAuthenticationToken;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.Set;

/**
 * Verifies reactive method security end-to-end: {@code @Secure} (framework sugar) and
 * {@code @PreAuthorize} (standard) both enforce fail-closed against the reactive security context.
 */
@SpringBootTest(classes = MethodSecurityIntegrationTest.TestApp.class,
        webEnvironment = SpringBootTest.WebEnvironment.NONE)
class MethodSecurityIntegrationTest {

    @Autowired
    SecuredService service;

    private static FireflyAuthenticationToken auth(String... authorities) {
        return new FireflyAuthenticationToken(
                SecurityPrincipal.builder().subject("u1").authorities(Set.of(authorities)).build());
    }

    @Test
    void secureDeniesWhenUnauthenticated() {
        StepVerifier.create(service.adminOnly())
                .expectError(AuthorizationDeniedException.class).verify();
    }

    @Test
    void secureAllowsWhenRequiredRolePresent() {
        StepVerifier.create(service.adminOnly()
                        .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth("admin"))))
                .expectNext("admin-ok").verifyComplete();
    }

    @Test
    void secureDeniesWhenRoleMissing() {
        StepVerifier.create(service.adminOnly()
                        .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth("teller"))))
                .expectError(AuthorizationDeniedException.class).verify();
    }

    @Test
    void preAuthorizeIsEnabled() {
        StepVerifier.create(service.tellerOnly()
                        .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth("teller"))))
                .expectNext("teller-ok").verifyComplete();
    }

    @Test
    void unannotatedMethodIsOpen() {
        StepVerifier.create(service.open()).expectNext("open").verifyComplete();
    }

    @SpringBootApplication
    static class TestApp {
        @Bean
        SecuredService securedService() {
            return new SecuredService();
        }
    }

    static class SecuredService {

        @Secure(roles = "admin")
        public Mono<String> adminOnly() {
            return Mono.just("admin-ok");
        }

        @PreAuthorize("hasAuthority('teller')")
        public Mono<String> tellerOnly() {
            return Mono.just("teller-ok");
        }

        public Mono<String> open() {
            return Mono.just("open");
        }
    }
}
