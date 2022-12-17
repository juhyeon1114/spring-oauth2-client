package security.springoauth2client;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {

    @GetMapping("/")
    public String Index() {
        return "index";
    }

    /**
     * [Authentication]
     * - oauth2Login() 로 인증받게 되면, OAuth2AuthenticationToken 객체가 Authentication 에 바인딩된다.
     */
    @GetMapping("/auth-user")
    public OAuth2User authUser(Authentication authentication) {
        /**
         * 인증 객체를 가져오는 2가지 방법
         */
        OAuth2AuthenticationToken authentication1 = (OAuth2AuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        OAuth2AuthenticationToken authentication2 = (OAuth2AuthenticationToken) authentication;

        OAuth2User oAuth2User = (OAuth2User) authentication2.getPrincipal();
        return oAuth2User;
    }

    @GetMapping("/auth-user/annotation")
    public OAuth2User authUserAnnotation(@AuthenticationPrincipal OAuth2User oAuth2User) {
        return oAuth2User;
    }

    @GetMapping("/auth-oidc-user/annotation")
    public OidcUser authOidcUser(@AuthenticationPrincipal OidcUser oidcUser) {
        return oidcUser;
    }


}

