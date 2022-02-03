package hello.security.oauth;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

    // 후처리를 위한 코드 -> google로 받은 userRequest data 에대한 후처리되는 함수
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        log.info("userRequest = {}", userRequest);
        log.info("getAccessToken = {}", userRequest.getAccessToken());
        // 어떤 oauth로 로그인 했는지 확인 가능
        log.info("getClientRegistration = {}", userRequest.getClientRegistration());
        // 구글에서 주는 제일 중요한 정보다
        // 구글 로그인 완료 -> code 리턴(Oauth-Client라이브러리) -> AccessToken 요청 ->
        // userRequest 정보 -> loadUser함수 호출 -> 구글로부터 회원 프로필 받아준다.
        log.info("getAttributes = {}", super.loadUser(userRequest).getAttributes());

        OAuth2User oAuth2User = super.loadUser(userRequest);
        // getAttributes를 이용하여 회원 가입을 강제로 해볼 예정정
       return super.loadUser(userRequest);
    }
}
