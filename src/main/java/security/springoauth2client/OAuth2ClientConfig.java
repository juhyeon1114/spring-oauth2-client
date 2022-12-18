package security.springoauth2client;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

/**
 * 2. oAuth2Client()
 */
@Configuration
@RequiredArgsConstructor
public class OAuth2ClientConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests().anyRequest().authenticated();
        http.oauth2Client(Customizer.withDefaults());
        return http.build();
    }
}

/**
 * 1. oAuth2Login()
 */
//@Configuration
//@RequiredArgsConstructor
//public class OAuth2ClientConfig {
//
//    private final ClientRegistrationRepository clientRegistrationRepository;
//
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http.authorizeHttpRequests()
//                .requestMatchers("/login").permitAll()
//                .requestMatchers("/home").permitAll()
//                .requestMatchers("/logout").permitAll()
//                .requestMatchers("/loginPage").permitAll()
//                .requestMatchers("/user").permitAll()
//                .requestMatchers("/oidc").permitAll()
//                .anyRequest()
//                .authenticated();
//
////        http.oauth2Login(config -> config
////                .loginPage("/login")
////                .authorizationEndpoint(authorizationEndpointConfig ->
////                        authorizationEndpointConfig.baseUri("/oauth2/v1/authorization")
////                )
////                .redirectionEndpoint(redirectionEndpointConfig ->
////                        redirectionEndpointConfig.baseUri("/login/v1/oauth2/code/*")
////                )
////        );
//
//        http.oauth2Login(Customizer.withDefaults());
//
////        http.oauth2Login(httpSecurityOAuth2LoginConfigurer -> httpSecurityOAuth2LoginConfigurer.authorizationEndpoint(
////                authorizationEndpointConfig -> authorizationEndpointConfig.authorizationRequestResolver(customOAuth2AuthorizationRequestResolver())
////        ));
//
//        http.logout()
//                .logoutSuccessHandler(logoutSuccessHandler())
//                .invalidateHttpSession(true)
//                .clearAuthentication(true)
//                .deleteCookies("JSESSIONID");
//
//        return http.build();
//    }
//
//    private LogoutSuccessHandler logoutSuccessHandler() {
//        OidcClientInitiatedLogoutSuccessHandler successHandler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
////        successHandler.setPostLogoutRedirectUri("http://localhost:8080/login");
//        successHandler.setPostLogoutRedirectUri("/home");
//        return successHandler;
//    }
//
//    private OAuth2AuthorizationRequestResolver customOAuth2AuthorizationRequestResolver() {
//        return new CustomOAuth2AuthorizationRequestResolver();
//    }
//
//}
