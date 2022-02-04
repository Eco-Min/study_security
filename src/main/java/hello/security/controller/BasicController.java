package hello.security.controller;

import hello.security.configure.auth.PrincipalDetails;
import hello.security.model.Role;
import hello.security.model.User;
import hello.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.security.Principal;

@Controller
@RequiredArgsConstructor
@Slf4j
public class BasicController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    /**
     * 서버 일반 처리 같은경우 UserDetails 를 사용
     */
    @GetMapping("/test/login")
    @ResponseBody
    public String testLogin(Authentication authentication,
                            @AuthenticationPrincipal UserDetails userDetails,
                            Principal principal) {
        log.info("/test/login =================");
        log.info("Authentication");
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        log.info("authentication = {} ", principalDetails.getUser());

        log.info("@AuthenticationPrincipal");
        log.info("userDetails = {}", userDetails.getUsername());

        log.info("@Principal");
        log.info("principal = {}", principal.getName());

        return "세션 정보 확인하기";
    }

    /**
     * 서버 oauth 처리 같은경우 OAuth2User 를 사용
     */
    @GetMapping("/test/oauth/login")
    @ResponseBody
    public String testOauthLogin(Authentication authentication,
                            @AuthenticationPrincipal OAuth2User oAuth2User,
                            Principal principal) {
        log.info("/test/oauth/login =================");
        log.info("Authentication");
        OAuth2User principalDetails = (OAuth2User) authentication.getPrincipal();
        log.info("authentication = {} ", principalDetails.getAttributes());

        log.info("@AuthenticationPrincipal");
        log.info("userDetails = {}", oAuth2User.getAttributes());

        log.info("@Principal");
        log.info("principal = {}", principal.getName());

        return "Oauth 세션 정보 확인하기";
    }

    @ResponseBody
    @GetMapping("/user")
    public String user(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        log.info("principalDetails.getUser() = {}", principalDetails.getUser());

        return "user";
    }

    @ResponseBody
    @GetMapping("/admin")
    public String admin() {
        return "admin";
    }

    @ResponseBody
    @GetMapping("/manager")
    public String manager() {
        return "manager";
    }

    @GetMapping("/loginForm")
    public String login(Principal principal) {
        if (principal != null) {
            return "redirect:/";
        }
        return "loginForm";
    }

    @GetMapping("/joinForm")
    public String joinForm(Principal principal) {
        if (principal != null) {
            return "redirect:/";
        }
        return "joinForm";
    }

    //    @ResponseBody
    @PostMapping("/join")
    public String join(User user) {
        user.setRole(Role.ROLE_USER);
        log.info("user = {}", user);
        String rawPassword = user.getPassword();
        String encPassword = bCryptPasswordEncoder.encode(rawPassword);
        user.setPassword(encPassword);
        userRepository.save(user);
        return "redirect:/loginForm";
    }

    @Secured("ROLE_ADMIN") //@EnableGlobalMethodSecurity 를 통해 @Secured 로 특정 메소드 접근 제한
    @ResponseBody
    @GetMapping("/info")
    public String info() {
        return "개인정보 : ";
    }

    //@EnableGlobalMethodSecurity 통해 접근 제한 함수가 시작전 security 정책이 걸립니다.
    @PreAuthorize("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
    @ResponseBody
    @GetMapping("/data")
    public String data() {
        return "데이터 정보 : ";
    }
}
