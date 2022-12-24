package io.abhishek;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	SecurityFilterChain chain(HttpSecurity httpSecurity) throws Exception {
		httpSecurity.csrf().disable().formLogin().and().authorizeHttpRequests().antMatchers("**/swagger-ui.html/**")
				.permitAll().antMatchers("/v3/**", "/actuator/**", "/webjars/**").permitAll()
				.antMatchers(HttpMethod.GET, "/get/**").hasAuthority("SCOPE_read").anyRequest().authenticated().and()
				.oauth2ResourceServer().jwt();

		return httpSecurity.build();
	}

	@Bean
	public UserDetailsService userDetails() {
		UserDetails user = User.withUsername("u").password("p").authorities("read").build();
		InMemoryUserDetailsManager mng = new InMemoryUserDetailsManager();
		mng.createUser(user);
		return mng;
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}

	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}
}
