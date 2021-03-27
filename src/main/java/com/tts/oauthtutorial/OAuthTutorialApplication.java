package com.tts.oauthtutorial;

import java.util.Collections;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
//import org.springframework.web.reactive.function.client.WebClient;

@SpringBootApplication
@RestController
public class OAuthTutorialApplication extends WebSecurityConfigurerAdapter {
	
	
	/* Tried completing the last section "generating a 401 in the server," but kept getting errors.
	 * I know I am supposed to create a WebClient instance, but I don't believe that I did correctly
	 * Each time I tried I was getting more errors
	 * I looked at the source code for this tutorial, but I couldn't tell whether or not they created 
	 * a WebClient instance 
	
	
	@Bean
	public WebClient rest(ClientRegistrationRepository clients, OAuth2AuthorizedClientRepository authz) {
		
	    ServletOAuth2AuthorizedClientExchangeFilterFunction oauth2 =
	            new ServletOAuth2AuthorizedClientExchangeFilterFunction(clients, authz);
	    return WebClient.builder()
	            .filter(oauth2).build();
	}
	
	@Bean
	public OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService(WebClient rest) {
		DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();
		return request -> {
			OAuth2User user = delegate.loadUser(request);
			if (!"github".equals(request.getClientRegistration().getRegistrationId())) {
				return user;
			}

			OAuth2AuthorizedClient client = new OAuth2AuthorizedClient
					(request.getClientRegistration(), user.getName(), request.getAccessToken());
			String url = user.getAttribute("organizations_url");
			List<Map<String, Object>> orgs = rest
					.get().uri(url)
					.attributes(oauth2AuthorizedClient(client))
					.retrieve()
					.bodyToMono(List.class)
					.block();

			if (orgs.stream().anyMatch(org -> "spring-projects".equals(org.get("login")))) {
				return user;
			}

			throw new OAuth2AuthenticationException(new OAuth2Error("invalid_token", "Not in Spring Team", ""));
		};
	}
	
	*/
	
	@GetMapping("/user")
	@ResponseBody
	public Map<String, Object> user(@AuthenticationPrincipal OAuth2User principal) {
		return Collections.singletonMap("name", principal.getAttribute("name"));
	}

	@GetMapping("/error")
	@ResponseBody
	public String error(HttpServletRequest request) {
		String message = (String) request.getSession().getAttribute("error.message");
		request.getSession().removeAttribute("error.message");
		return message;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		SimpleUrlAuthenticationFailureHandler handler = new SimpleUrlAuthenticationFailureHandler("/");
		

		http.antMatcher("/**")
			.authorizeRequests(a -> a
				.antMatchers("/", "/error", "/webjars/**").permitAll()
				.anyRequest().authenticated()
			)
			.exceptionHandling(e -> e
				.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
			)
			.csrf(c -> c
				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
			)
			.logout(l -> l
				.logoutSuccessUrl("/").permitAll()
			)
			.oauth2Login(o -> o
				.failureHandler((request, response, exception) -> {
					request.getSession().setAttribute("error.message", exception.getMessage());
					handler.onAuthenticationFailure(request, response, exception);
				})
			);
	}
	
	

	public static void main(String[] args) {
		SpringApplication.run(OAuthTutorialApplication.class, args);
	}

}
