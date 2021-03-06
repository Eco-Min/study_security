package hello.security.configure.auth;

/*
security 가 /login 주소 요청이 오면 낚아채서 로그인을 진행 시킨다.
로그인을 진행이 완료가 되면 session을 만들어 줍니다. (Security ContextHolder)
오브젝트 타입 => Authentication 타입 객체
Authentication 안에 User 정보가 있어야됨
User 오브젝트 타입 => UserDetails 타입 객체

Security Session => Authentication => UserDetails(PrincipalDetails)
*/

import hello.security.model.Role;
import hello.security.model.User;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

@Getter
public class PrincipalDetails implements UserDetails, OAuth2User {

    private User user;
    // Oauth2User로 로그인을 받을시 attributes 로 저장
    private Map<String, Object> attributes;

    //일반 로그인시
    public PrincipalDetails(User user) {
        this.user = user;
    }
    // Oauth 로그인시
    public PrincipalDetails(User user, Map<String, Object> attributes) {
        this.user = user;
        this.attributes = attributes;
    }

    // 해당 User의 권한을 리턴하는 곳
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collect = new ArrayList<>();
        collect.add((GrantedAuthority) () -> {
            Role role = user.getRole();
            return role.toString();
        });
        return collect;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    // 우리 사이트 1년동안 회원이 로그인 X -> 휴면계정으로 전환 시 false 로 지정
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public String getName() {
        return (String) attributes.get("sub");
    }
}
