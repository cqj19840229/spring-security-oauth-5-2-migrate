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
package sample;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configuration.oauth2.server.authorization.OAuth2AuthorizationServerSecurity;
import org.springframework.security.config.annotation.web.configurers.DefaultLoginPageConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebSecurity
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	@Bean
	public RegisteredClientRepository registeredClientRepository(){
		//FilterSecurityInterceptor fsi;
		  RegisteredClientRepository registeredClientRepository =new InMemoryRegisteredClientRepository(RegisteredClient.withId("test")
				.clientId("messaging-client")
				.clientSecret("secret")
				//.redirectUri("http://localhost:8080/authorized")
				.redirectUri("http://localhost:8080/client/account/redirect")
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				  .scope("message.read")
				  .scope("message.write")
				.build()
		);
		  return registeredClientRepository;
	}

	@Bean
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
//		RegisteredClientRepository registeredClientRepository =registeredClientRepository();
//		OAuth2AuthorizationService authorizationService = new InMemoryOAuth2AuthorizationService();
		OAuth2AuthorizationServerConfigurer oAuth2AuthorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer<>();
//		http.setSharedObject(AuthenticationManager.class,authenticationManagerBean());
//		oAuth2AuthorizationServerConfigurer.setBuilder(http);
//		oAuth2AuthorizationServerConfigurer.init(http);
//		oAuth2AuthorizationServerConfigurer.configure(http);
//		oAuth2AuthorizationServerConfigurer.registeredClientRepository(registeredClientRepository);
//		oAuth2AuthorizationServerConfigurer.authorizationService(authorizationService);

		//this.ob

		http
				.csrf().disable()
				.authorizeRequests()
				//.antMatchers("/", "/home", "/login").permitAll()
				.anyRequest().authenticated()
				.and()
				//.oauth2Login(form->form.loginPage("login").permitAll())
				.formLogin(form->form.loginPage("/login").permitAll())
				.apply(oAuth2AuthorizationServerConfigurer);

		oAuth2AuthorizationServerConfigurer.registeredClientRepository(registeredClientRepository());

	}

	private JWKSet generateJwkSet() throws JOSEException {
		JWK jwk = new RSAKeyGenerator(2048).keyID("minimal-ASA").keyUse(KeyUse.SIGNATURE).generate();
		return new JWKSet(jwk);
	}

	@Bean
	public UserDetailsService users() {
		UserDetails user = User.withDefaultPasswordEncoder()
				.username("user")
				.password("123456")
				.roles("USER")
				.build();
		return  new InMemoryUserDetailsManager(user);
	}

	//segmentfault
//	@Override
//	public void configure(HttpSecurity http) throws Exception {
//		http.csrf().disable();
//		http
//				.requestMatchers().antMatchers("/oauth/**","/login/**","/logout/**")
//				.and()
//				.authorizeRequests()
//				.antMatchers("/oauth/**").authenticated()
//				.and()
//				.formLogin().permitAll(); //新增login form支持用户登录及授权
//	}


//	@Override
//	protected void configure(HttpSecurity http) throws Exception {
////		http
////				.authorizeRequests(authorize -> authorize
////						.anyRequest().authenticated()
////				)
////				.oauth2Login(withDefaults());
//
//		http
//				.requestMatchers()
//				//.antMatchers("/", "/home", "/login", "/oauth2/**")
//				.antMatchers("/", "/home", "/login")
//				.and()
//				.authorizeRequests()
//				.anyRequest().permitAll()
//				.and()
//				.oauth2Login(oauth2 -> oauth2
//						.loginPage("/login"))
//				.apply(new OAuth2AuthorizationServerConfigurer());
//
////				http.authorizeRequests(authorizeRequests ->
////						authorizeRequests
////								.anyRequest().authenticated()
////				).apply(new OAuth2AuthorizationServerConfigurer());
//	}




//	@Override
//	protected void configure(HttpSecurity http) throws Exception {
//
//		OAuth2AuthorizationService authorizationService = new InMemoryOAuth2AuthorizationService();
//		OAuth2AuthorizationServerConfigurer oAuth2AuthorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer<>();
//		oAuth2AuthorizationServerConfigurer.configure(http);
//		oAuth2AuthorizationServerConfigurer.registeredClientRepository(registeredClientRepository());
//		oAuth2AuthorizationServerConfigurer.authorizationService(authorizationService);
//		//http.removeConfigurer()
//		http.oauth2Login().and()
//		.authorizeRequests(authorizeRequests ->
//				 				authorizeRequests
//									.anyRequest().authenticated()
//						//	).apply(new OAuth2AuthorizationServerConfigurer());
//							).apply(oAuth2AuthorizationServerConfigurer);
//	 			//.oauth2Client(withDefaults());
////		http
////				.oauth2Client(oauth2 -> oauth2
////						.clientRegistrationRepository(this.clientRegistrationRepository())
////						.authorizedClientRepository(this.authorizedClientRepository())
////						.authorizedClientService(this.authorizedClientService())
////						.authorizationCodeGrant(codeGrant -> codeGrant
////								.authorizationRequestRepository(this.authorizationRequestRepository())
////								.authorizationRequestResolver(this.authorizationRequestResolver())
////								.accessTokenResponseClient(this.accessTokenResponseClient())
////						)
////				);
//	}


	//	@Override
//	protected void configure(HttpSecurity http) throws Exception {
//		http.addFilterBefore(new JwkSetEndpointFilter(generateJwkSet()), LogoutFilter.class);
//	}


}
