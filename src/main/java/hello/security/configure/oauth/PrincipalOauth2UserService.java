package hello.security.configure.oauth;

import hello.security.configure.auth.PrincipalDetails;
import hello.security.configure.oauth.provider.FacebookUserInfo;
import hello.security.configure.oauth.provider.GoogleUserInfo;
import hello.security.configure.oauth.provider.NaverUserInfo;
import hello.security.configure.oauth.provider.Oauth2UserInfo;
import hello.security.model.Role;
import hello.security.model.User;
import hello.security.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@Slf4j
public class PrincipalOauth2UserService extends DefaultOAuth2UserService {

/*    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;*/

    @Autowired
    private UserRepository userRepository;

    // 후처리를 위한 코드 -> google로 받은 userRequest data 에대한 후처리되는 함수
    // 함수 종료시 @AuthenticationPrincipal 어노테이션이 생성
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        log.info("userRequest = {}", userRequest);
        log.info("getAccessToken = {}", userRequest.getAccessToken());
        // 어떤 oauth로 로그인 했는지 확인 가능
        log.info("getClientRegistration = {}", userRequest.getClientRegistration());

        OAuth2User oAuth2User = super.loadUser(userRequest);
        // 구글에서 주는 제일 중요한 정보다
        // 구글 로그인 완료 -> code 리턴(Oauth-Client라이브러리) -> AccessToken 요청 ->
        // userRequest 정보 -> loadUser함수 호출 -> 구글로부터 회원 프로필 받아준다.
        log.info("getAttributes = {}", oAuth2User.getAttributes());

        Oauth2UserInfo oauth2UserInfo = null;
        if (userRequest.getClientRegistration().getRegistrationId().equals("google")) {
            log.info("google 요청");
            oauth2UserInfo = new GoogleUserInfo(oAuth2User.getAttributes());
        } else if (userRequest.getClientRegistration().getRegistrationId().equals("facebook")) {
            log.info("facebook 요청");
            oauth2UserInfo = new FacebookUserInfo(oAuth2User.getAttributes());
        }else if (userRequest.getClientRegistration().getRegistrationId().equals("naver")){
            log.info("naver 요청");
            oauth2UserInfo = new NaverUserInfo((Map<String, Object>) oAuth2User.getAttributes().get("response"));
        }
        else {
            log.info("우리는 google, facebook, naver 만 지원");
        }

        // getAttributes를 이용하여 회원 가입을 강제로 해볼 예정정
        String username = oauth2UserInfo.getProvider() + "_" + oauth2UserInfo.getProviderId();
        User userEntity = userRepository.findByUsername(username);
        if (userEntity == null) {
            userEntity = new User(username,
                    new BCryptPasswordEncoder().encode("zxcv"),
                    oauth2UserInfo.getEmail(),
                    Role.ROLE_USER,
                    oauth2UserInfo.getProvider(),
                    oauth2UserInfo.getProviderId());
            userRepository.save(userEntity);
        } else {
            log.info("자동회원가입이 완료되어 로그인을 합니다.");
        }

//       return super.loadUser(userRequest);
        return new PrincipalDetails(userEntity, oAuth2User.getAttributes()); // 예가 Authentication 객체안에 들어감
    }
}
