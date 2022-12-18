package security.springoauth2client;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

//public class CustomOAuth2AuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {
//
//    private String baseUri;
//    private ClientRegistrationRepository clientRegistrationRepository;
//    private DefaultOAuth2AuthorizationRequestResolver authRequestResolver;
//    private AuthorizationRequestMa authorizationRequestMatcher;
//
//    public CustomOAuth2AuthorizationRequestResolver(
//            String baseUri,
//            ClientRegistrationRepository clientRegistrationRepository
//    ) {
//        this.baseUri = baseUri;
//        this.clientRegistrationRepository = clientRegistrationRepository;
//        this.authRequestResolver = new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, baseUri);
//    }
//
//    @Override
//    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
//        return null;
//    }
//
//    @Override
//    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
//        return null;
//    }
//}
