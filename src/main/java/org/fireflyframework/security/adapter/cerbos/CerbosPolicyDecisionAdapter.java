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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.fireflyframework.security.api.domain.Decision;
import org.fireflyframework.security.api.domain.SecurityPrincipal;
import org.fireflyframework.security.spi.PolicyDecisionPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

/**
 * {@link PolicyDecisionPort} backed by Cerbos. Maps the framework's authorization request to a
 * Cerbos {@code CheckResources} call (principal + resource + action) and interprets the per-action
 * effect. The {@code resource} argument is parsed as {@code "kind:id"}. <strong>Fail-closed</strong>:
 * a transport error is indeterminate (denied), and anything other than {@code EFFECT_ALLOW} denies.
 */
public class CerbosPolicyDecisionAdapter implements PolicyDecisionPort {

    private static final Logger log = LoggerFactory.getLogger(CerbosPolicyDecisionAdapter.class);
    private static final String POLICY_VERSION = "default";

    private final WebClient webClient;

    public CerbosPolicyDecisionAdapter(WebClient webClient) {
        this.webClient = webClient;
    }

    @Override
    public Mono<Decision> authorize(SecurityPrincipal principal, String action, String resource, Map<String, Object> context) {
        int sep = resource.indexOf(':');
        String kind = sep > 0 ? resource.substring(0, sep) : resource;
        String id = sep > 0 ? resource.substring(sep + 1) : resource;

        List<String> roles = principal.authorities().isEmpty()
                ? List.of("_anonymous") : List.copyOf(principal.authorities());

        Map<String, Object> body = Map.of(
                "requestId", "firefly",
                "principal", Map.of(
                        "id", principal.subject() == null ? "anonymous" : principal.subject(),
                        "roles", roles,
                        "policyVersion", POLICY_VERSION),
                "resources", List.of(Map.of(
                        "actions", List.of(action),
                        "resource", Map.of(
                                "kind", kind,
                                "id", id,
                                "policyVersion", POLICY_VERSION,
                                "attr", context == null ? Map.of() : context))));

        return webClient.post()
                .uri("/api/check/resources")
                .bodyValue(body)
                .retrieve()
                .bodyToMono(CheckResourcesResponse.class)
                .map(response -> "EFFECT_ALLOW".equals(response.effectFor(action))
                        ? Decision.permit()
                        : Decision.deny("denied by Cerbos policy"))
                .onErrorResume(error -> {
                    log.warn("Cerbos check failed; failing closed: {}", error.getMessage());
                    return Mono.just(Decision.indeterminate("Cerbos error: " + error.getMessage()));
                });
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    record CheckResourcesResponse(List<Result> results) {

        String effectFor(String action) {
            if (results == null || results.isEmpty() || results.get(0).actions() == null) {
                return null;
            }
            return results.get(0).actions().get(action);
        }

        @JsonIgnoreProperties(ignoreUnknown = true)
        record Result(Map<String, String> actions) {
        }
    }
}
