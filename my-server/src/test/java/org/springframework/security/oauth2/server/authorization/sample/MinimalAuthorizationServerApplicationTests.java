/*
 * Copyright 2020 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.server.authorization.sample;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import sample.JwkSetEndpointFilter;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public class MinimalAuthorizationServerApplicationTests {
	private RestTemplate rest = new RestTemplate();

	@LocalServerPort
	private int serverPort;

	@Test
	void requestWhenNotAuthenticatedThenJwkSetEndpointStillAccessible() {
		ResponseEntity<String> responseEntity = this.rest.getForEntity(
				"http://localhost:" + this.serverPort + JwkSetEndpointFilter.DEFAULT_JWK_SET_URI, String.class);
		assertThat(responseEntity.getStatusCode()).isEqualTo(HttpStatus.OK);
	}
}
