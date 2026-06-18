# Firefly Framework - Security Method Policy

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-21%2B-orange.svg)](https://openjdk.org)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.x-green.svg)](https://spring.io/projects/spring-boot)
[![Spring Security](https://img.shields.io/badge/Spring%20Security-6.x-brightgreen.svg)](https://spring.io/projects/spring-security)

> Reactive method-level authorization for Spring WebFlux. A single auto-configuration turns on Spring Security's reactive method interceptors (`@PreAuthorize`/`@PostAuthorize`) and registers the framework's `@Secure` interceptor as ergonomic, fail-closed sugar on top of them — no security code, and method calls deny by default unless the validated principal satisfies the requirement.

---

## Table of Contents

- [Overview](#overview)
- [Where it sits in the platform](#where-it-sits-in-the-platform)
- [What it provides](#what-it-provides)
- [Key types](#key-types)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [How `@Secure` is evaluated](#how-secure-is-evaluated)
- [Testing](#testing)
- [License](#license)

## Overview

This module is the **method-security binding** of the Firefly hexagonal security platform. Where the resource-server module guards the *edge* (every inbound request must present a signature-validated bearer token before reaching a handler), this module guards individual *service methods*, so authorization can be expressed declaratively next to the business logic it protects.

It does two things. First, it switches on Spring Security 6's reactive method security — `@EnableReactiveMethodSecurity` — so the standard `@PreAuthorize`/`@PostAuthorize` annotations are enforced against the reactive security context. Second, it contributes a `@Secure` method interceptor that resolves the framework's `@Secure` annotation (declared in `security-api`) and evaluates it through the framework-neutral `SecureAuthorizationEvaluator` from `security-core`. `@Secure` is product-agnostic, fail-closed declarative authorization: a method (or its declaring class) denies unless the current `SecurityPrincipal` holds the declared roles, scopes, permissions, and/or satisfies an optional SpEL expression.

The whole module is one `@AutoConfiguration` class plus a single `ReactiveAuthorizationManager`. The interceptor bean is contributed unconditionally as infrastructure, but it composes cleanly with native Spring annotations — `@Secure` and `@PreAuthorize` can coexist on the same bean.

## Where it sits in the platform

The security platform is layered hexagonally; dependencies point inward, and providers attach as outboard adapters:

```
security-api  →  security-spi  →  security-core  →  security-webflux  →  security-method-policy  →  adapters
 (ports +         (driven           (neutral          (reactive             (this module:              (Vault, KMS,
  domain,          ports)            engine,            Spring Security        @EnableReactiveMethod-     OPA, Keycloak,
  @Secure)                           SecureAuth-        bindings)              Security + @Secure         internal-db, …)
                                     Evaluator)                                interceptor)
```

- **`security-api`** defines the domain (`SecurityPrincipal`) and the `@Secure` annotation this module enforces.
- **`security-core`** supplies the framework-neutral engine: `SecureRequirement` (a neutral view of `@Secure`) and `SecureAuthorizationEvaluator`, which this module calls to render an allow/deny `Decision`.
- **`security-webflux`** supplies the reactive Spring Security glue — `FireflyAuthenticationToken` (carrying a rich `SecurityPrincipal`) and `PrincipalSupport`, which recovers a `SecurityPrincipal` from any Spring `Authentication`.
- **This module** binds those into Spring Security's reactive method-interception machinery and is delivered to applications transitively via the application starter.
- **Adapters** are unaffected; method security reads whatever principal the edge produced.

This module depends only on `security-core` and `security-webflux` (which transitively bring `-spi` and `-api`) plus `spring-security-config` and `spring-boot-autoconfigure`. It imports no vendor SDK.

## What it provides

`MethodSecurityAutoConfiguration` (annotated `@AutoConfiguration @EnableReactiveMethodSecurity`) contributes:

- **Reactive method security**, by carrying `@EnableReactiveMethodSecurity`. This enables Spring's standard `@PreAuthorize`/`@PostAuthorize` reactive interceptors against `ReactiveSecurityContextHolder`.
- **The `@Secure` interceptor** — a single `AuthorizationManagerBeforeReactiveMethodInterceptor` bean (`fireflySecureMethodInterceptor`, registered with `BeanDefinition.ROLE_INFRASTRUCTURE`). Its pointcut matches the `@Secure` annotation on either a method or its declaring type (a `ComposablePointcut` union of two `AnnotationMatchingPointcut`s), and it delegates the allow/deny decision to `SecureMethodAuthorizationManager`.

`SecureMethodAuthorizationManager` is a `ReactiveAuthorizationManager<MethodInvocation>` that:

1. Resolves the effective `@Secure` annotation — method-level first (`AnnotatedElementUtils.findMergedAnnotation`), then the target class (via `AopUtils.getTargetClass`). If none is present, it permits (so the interceptor is inert on unannotated methods).
2. Converts the annotation to a neutral `SecureRequirement` (`SecureRequirement.from(...)`).
3. Extracts a `SecurityPrincipal` from the current `Authentication` via `PrincipalSupport.extract(...)`, filtered on `Authentication::isAuthenticated`.
4. Renders the decision through `SecureAuthorizationEvaluator.evaluate(...)` and returns its `granted()` flag.

It is **fail-closed**: an unauthenticated caller (empty/anonymous context) yields `new AuthorizationDecision(false)` via `defaultIfEmpty`, and a principal that does not satisfy the requirement is denied. A denial surfaces to the caller as Spring Security's `AuthorizationDeniedException` on the reactive stream.

## Key types

| Type | Role |
| --- | --- |
| `MethodSecurityAutoConfiguration` | `@AutoConfiguration @EnableReactiveMethodSecurity` entry point; enables reactive method security and registers the `@Secure` interceptor. |
| `SecureMethodAuthorizationManager` | `ReactiveAuthorizationManager<MethodInvocation>` that resolves `@Secure`, builds a `SecureRequirement`, and evaluates it against the reactive `SecurityPrincipal`, fail-closed. |

Annotation enforced (from `security-api`): `@Secure` (`roles`, `scopes`, `permissions`, `requireAllRoles`/`requireAllScopes`/`requireAllPermissions`, `expression`). Engine consumed (from `security-core`): `SecureRequirement`, `SecureAuthorizationEvaluator`, `Decision`. Reactive glue consumed (from `security-webflux`): `PrincipalSupport`, `FireflyAuthenticationToken`. Domain (from `security-api`): `SecurityPrincipal`.

The auto-configuration is registered via `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`.

## Requirements

- Java 21+
- Spring Boot 3.x, Spring Security 6.x
- A reactive web stack (Spring WebFlux) with a populated `ReactiveSecurityContextHolder` — typically established by the resource-server module, which places a `FireflyAuthenticationToken` carrying a `SecurityPrincipal` into the reactive context.

## Installation

The version is managed by the Firefly parent/BOM, so you can usually omit it. In a Firefly application this module is pulled in transitively by the application starter; depend on it directly only when enabling method security standalone:

```xml
<dependency>
    <groupId>org.fireflyframework</groupId>
    <artifactId>fireflyframework-security-method-policy</artifactId>
</dependency>
```

If you are not inheriting the Firefly parent, pin the version explicitly:

```xml
<dependency>
    <groupId>org.fireflyframework</groupId>
    <artifactId>fireflyframework-security-method-policy</artifactId>
    <version>26.06.01</version>
</dependency>
```

## Quick Start

With the module on the classpath, reactive method security is active with **zero code**. Annotate the methods (or classes) you want to protect:

```java
import org.fireflyframework.security.api.annotation.Secure;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

@Service
class AccountService {

    // Framework sugar: ANY of the listed roles suffices (fail-closed).
    @Secure(roles = "admin")
    Mono<Account> close(String accountId) {
        return ...;
    }

    // Require a scope AND a fine-grained permission, both fully matched.
    @Secure(scopes = "accounts.write", permissions = "account:close", requireAllPermissions = true)
    Mono<Void> freeze(String accountId) {
        return ...;
    }

    // Standard Spring annotation, enforced against the same reactive context.
    @PreAuthorize("hasAuthority('teller')")
    Mono<Balance> balance(String accountId) {
        return ...;
    }
}
```

`@Secure` accepts `roles`, `scopes`, `permissions`, and an optional SpEL `expression`. Across those dimensions **all** declared dimensions must pass (AND); within a single dimension the `requireAll*` flag switches between ANY (default) and ALL matching. An empty `@Secure` simply requires an authenticated principal.

## How `@Secure` is evaluated

```
Mono<T> method() guarded by @Secure
   → fireflySecureMethodInterceptor (pointcut: @Secure on method or class)
   → SecureMethodAuthorizationManager.check(...)
      → resolve @Secure (method first, then target class)
      → SecureRequirement.from(secure)
      → PrincipalSupport.extract(Authentication)  // from ReactiveSecurityContextHolder
      → SecureAuthorizationEvaluator.evaluate(principal, requirement) → Decision
   → AuthorizationDecision(granted)
   → granted ? proceed : AuthorizationDeniedException
```

A `null`/unauthenticated principal is denied; each declared dimension is checked in turn (roles, scopes, permissions, then expression), and a failing or throwing SpEL expression denies. Only a principal that satisfies every declared dimension reaches the method body.

## Testing

The module ships a `@SpringBootTest` integration test, `MethodSecurityIntegrationTest` (`webEnvironment = NONE`), that boots a real Spring context with the real `MethodSecurityAutoConfiguration` and drives a `SecuredService` whose methods are annotated with `@Secure` and `@PreAuthorize`. It exercises both annotation styles end to end against the reactive security context — establishing identity with `ReactiveSecurityContextHolder.withAuthentication(...)` and a `FireflyAuthenticationToken` built over a `SecurityPrincipal`, then asserting outcomes with `StepVerifier`:

- **Denied (unauthenticated)** — `@Secure(roles = "admin")` with no authentication in context errors with `AuthorizationDeniedException` (fail-closed default).
- **Allowed (role present)** — the same method, with an `admin`-authorized principal in context, emits its value.
- **Denied (role missing)** — the same method, with a `teller`-only principal, errors with `AuthorizationDeniedException`.
- **`@PreAuthorize` enabled** — `@PreAuthorize("hasAuthority('teller')")` permits a `teller` principal, proving native Spring method security is active alongside `@Secure`.
- **Unannotated method is open** — a method with no annotation runs without an authenticated context, proving the interceptor is inert where `@Secure` is absent.

These mirror the platform's negative-path verification strategy: the unauthenticated and missing-authority deny paths are proven, not assumed.

## License

Copyright 2024-2026 Firefly Software Foundation.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
