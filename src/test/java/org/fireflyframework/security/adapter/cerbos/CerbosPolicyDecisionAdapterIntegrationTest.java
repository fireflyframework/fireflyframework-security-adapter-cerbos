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

package org.fireflyframework.security.adapter.cerbos;

import org.fireflyframework.security.api.domain.SecurityPrincipal;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.MountableFile;
import reactor.test.StepVerifier;

import java.util.Map;
import java.util.Set;

/**
 * Real integration test of the Cerbos ABAC adapter against a live Cerbos server (Docker) loaded
 * with a resource policy that permits {@code view} on {@code document} only for the {@code admin}
 * role. Verifies permit/deny outcomes.
 */
@Testcontainers
class CerbosPolicyDecisionAdapterIntegrationTest {

    @Container
    static final GenericContainer<?> CERBOS = new GenericContainer<>("cerbos/cerbos:latest")
            .withExposedPorts(3592)
            .withCopyFileToContainer(MountableFile.forClasspathResource("cerbos/config.yaml"), "/conf/.cerbos.yaml")
            .withCopyFileToContainer(MountableFile.forClasspathResource("cerbos/policies/document.yaml"), "/policies/document.yaml")
            .withCommand("server", "--config=/conf/.cerbos.yaml")
            .waitingFor(Wait.forHttp("/_cerbos/health").forPort(3592).forStatusCode(200));

    private CerbosPolicyDecisionAdapter adapter() {
        String baseUrl = "http://" + CERBOS.getHost() + ":" + CERBOS.getMappedPort(3592);
        return new CerbosPolicyDecisionAdapter(WebClient.create(baseUrl));
    }

    private SecurityPrincipal principal(Set<String> roles) {
        return SecurityPrincipal.builder().subject("alice").authorities(roles).build();
    }

    @Test
    void permitsAdminRole() {
        StepVerifier.create(adapter().authorize(principal(Set.of("admin")), "view", "document:1", Map.of()))
                .expectNextMatches(d -> d.granted())
                .verifyComplete();
    }

    @Test
    void deniesNonAdminRole() {
        StepVerifier.create(adapter().authorize(principal(Set.of("teller")), "view", "document:1", Map.of()))
                .expectNextMatches(d -> !d.granted())
                .verifyComplete();
    }
}
