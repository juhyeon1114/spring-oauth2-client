package security.springoauth2client;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@RequiredArgsConstructor
public class HomeController {

    private final OAuth2AuthorizedClientService oAuth2AuthorizedClientService;

    @GetMapping("/home")
    public String home(
            Model model,
           @RegisteredOAuth2AuthorizedClient("keycloak") OAuth2AuthorizedClient authorizedClient
   ) {

        model.addAttribute("AccessToken", authorizedClient.getAccessToken());
        model.addAttribute("RefreshToken", authorizedClient.getRefreshToken());

        return "home";

    }

}
