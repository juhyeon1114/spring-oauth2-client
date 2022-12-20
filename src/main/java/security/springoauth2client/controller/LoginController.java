package security.springoauth2client.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizationSuccessHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.time.Clock;
import java.time.Duration;

@Controller
@RequiredArgsConstructor
public class LoginController {

    private final DefaultOAuth2AuthorizedClientManager oAuth2AuthorizedClientManager;
    private final OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository;
    private Duration clockSkew = Duration.ofSeconds(60);
    private Clock clock = Clock.systemUTC();


    @GetMapping("/oauth2Login")
    public String oauth2Login(HttpServletRequest request, HttpServletResponse response, Model model) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest
                .withClientRegistrationId("keycloak")
                .principal(authentication)
                .attribute(HttpServletRequest.class.getName(), request)
                .attribute(HttpServletResponse.class.getName(), response)
                .build();

        OAuth2AuthorizationSuccessHandler successHandler = ((authorizedClient, principal, attributes) -> {
            oAuth2AuthorizedClientRepository
                    .saveAuthorizedClient(
                            authorizedClient,
                            principal,
                            (HttpServletRequest) attributes.get(HttpServletRequest.class.getName()),
                            (HttpServletResponse) attributes.get(HttpServletResponse.class.getName())
                    );

            System.out.println("Auth");
        });

        oAuth2AuthorizedClientManager.setAuthorizationSuccessHandler(successHandler);

        OAuth2AuthorizedClient authorizedClient = oAuth2AuthorizedClientManager.authorize(authorizeRequest);

        // refresh 토큰으로 재발급 받기
        if (
                authorizedClient != null &&
                hasTokenExpired(authorizedClient.getAccessToken()) &&
                authorizedClient.getRefreshToken() != null
        ) {

            ClientRegistration clientRegistration = ClientRegistration
                    .withClientRegistration(authorizedClient.getClientRegistration())
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .build();

            OAuth2AuthorizedClient oAuth2AuthorizedClient = new OAuth2AuthorizedClient(
                    clientRegistration,
                    authorizedClient.getPrincipalName(),
                    authorizedClient.getAccessToken()
            );

            OAuth2AuthorizeRequest authorizeRequest2 = OAuth2AuthorizeRequest
                    .withAuthorizedClient(oAuth2AuthorizedClient)
                    .principal(authentication)
                    .attribute(HttpServletRequest.class.getName(), request)
                    .attribute(HttpServletResponse.class.getName(), response)
                    .build();

            oAuth2AuthorizedClientManager.authorize(authorizeRequest2);
        }

        model.addAttribute("authorizedClient", authorizedClient.getAccessToken().getTokenValue());

        return "home";
    }

    private boolean hasTokenExpired(OAuth2Token token) {
        return clock.instant().isAfter(token.getExpiresAt().minus(clockSkew));
    }

    @GetMapping("/logout")
    public String logout(Authentication authentication, HttpServletRequest request, HttpServletResponse response) {
        SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
        logoutHandler.logout(request, response, authentication);

        return "redirect:/";
    }

}
