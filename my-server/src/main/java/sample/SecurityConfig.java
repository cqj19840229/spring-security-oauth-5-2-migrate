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

//	@Bean
//	public AuthenticationManager authenticationManagerBean() throws Exception {
//	      return super.authenticationManagerBean();
//	}

		//@Bean
//	public WebSecurityConfigurer<WebSecurity> defaultOAuth2AuthorizationServerSecurity() {
//		return new OAuth2AuthorizationServerSecurity();
//	}

//	http
//			.csrf().and()
//				.addFilter(new WebAsyncManagerIntegrationFilter())
//			.exceptionHandling().and()
//				.headers().and()
//				.sessionManagement().and()
//				.securityContext().and()
//				.requestCache().and()
//				.anonymous().and()
//				.servletApi().and()
//				.apply(new DefaultLoginPageConfigurer<>()).and()
//				.logout();

	@Bean
	public RegisteredClientRepository registeredClientRepository(){
		  RegisteredClientRepository registeredClientRepository =new InMemoryRegisteredClientRepository(RegisteredClient.withId("test")
				.clientId("messaging-client")
				.clientSecret("secrect")
				.redirectUri("http://localhost:8080/authorized")
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				  .scope("message.read")
				  .scope("message.write")
				.build()
		);
		  return registeredClientRepository;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				.cors()
				.and()
				.csrf()
				.disable()
				.authorizeRequests()
				.antMatchers("/", "/home", "/login").permitAll()
//				.antMatchers("/", "/home", "/login", "/oauth2/**").permitAll()
				.anyRequest()
				.authenticated()
				.and()
				.oauth2Login(oauth2 -> oauth2
						.loginPage("/login"))
				.apply(new OAuth2AuthorizationServerConfigurer());
			//	.and()
			//	.sessionManagement()
			//	.sessionCreationPolicy(SessionCreationPolicy.STATELESS);

		//http.addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);


//		CustomSecurityAttributeTO security = customYmlConfig.getSecurity();
//		AntMatchersPOJO antMatchers = security.getAntMatchers();
//		String[] permitAll = antMatchers.getPermitAll();
//		List<InterceptPOJO> intercepts = antMatchers.getIntercept();

		//登录
//		http.httpBasic().and()
//				//认证
//				.authorizeRequests()
//				//.antMatchers("/", "/home", "/login", "/oauth2/**")
//				//.permitAll()
//				.and()
//				//关闭跨站维护
//				.csrf().disable()
//				//.apply(validateCodeSecurityConfig)
//				//.and()
//				.apply(new OAuth2AuthorizationServerConfigurer());


//		ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry config = http.authorizeRequests();

//		if (CollectionUtils.isNotEmpty(intercepts)) {
//			for (InterceptPOJO intercept : intercepts) {
//				config.antMatchers(intercept.getHttpMethod(), intercept.getUrl()).
//						hasRole(intercept.getRole());
//			}
//		}
//		config.anyRequest()//任何请求
//				.authenticated();//都需要身份认证
	}


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
//		http
////				.requestMatchers()
////				// 必须登录过的用户才可以进行 oauth2 的授权码申请
////				.antMatchers("/", "/home", "/login", "/oauth2/**")
////				// .antMatchers("/", "/home", "/login", "/oauth/authorize")
////				.and()
////				.authorizeRequests()
////				.anyRequest().permitAll()
////				.and()
//				.formLogin()
//				.loginPage("/login")
//				//.and()
//				//.httpBasic()
//				//.disable()
//				//.exceptionHandling()
//				//.accessDeniedPage("/login?authorization_error=true")
//				.and()
//				// TODO: put CSRF protection back into this controller
//				.csrf()
//				.requireCsrfProtectionMatcher(new AntPathRequestMatcher("/oauth2/authorize"))
//				.disable()
//
//				.authorizeRequests(authorizeRequests ->
//						authorizeRequests
//								.anyRequest().authenticated()
//				).apply(new OAuth2AuthorizationServerConfigurer())
//
//		;
//		;
//
//		//OAuth2AuthorizationService authorizationService = new InMemoryOAuth2AuthorizationService();
////		OAuth2AuthorizationServerConfigurer oAuth2AuthorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer<>();
////		oAuth2AuthorizationServerConfigurer.configure(http);
//		//oAuth2AuthorizationServerConfigurer.registeredClientRepository(registeredClientRepository();
//		//oAuth2AuthorizationServerConfigurer.authorizationService(authorizationService);
//		//http.removeConfigurer()
////		http.oauth2Login().and()
////		.authorizeRequests(authorizeRequests ->
////				 				authorizeRequests
////									.anyRequest().authenticated()
////							).apply(new OAuth2AuthorizationServerConfigurer());
//							//).apply(oAuth2AuthorizationServerConfigurer);
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

	private JWKSet generateJwkSet() throws JOSEException {
		JWK jwk = new RSAKeyGenerator(2048).keyID("minimal-ASA").keyUse(KeyUse.SIGNATURE).generate();
		return new JWKSet(jwk);
	}

	@Bean
	public UserDetailsService users() {
		UserDetails user = User.withDefaultPasswordEncoder()
				.username("user1")
				.password("password")
				.roles("USER")
				.build();
		return  new InMemoryUserDetailsManager(user);
	}
}
