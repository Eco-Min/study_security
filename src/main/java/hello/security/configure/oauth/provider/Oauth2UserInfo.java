package hello.security.configure.oauth.provider;

import org.springframework.stereotype.Component;

public interface Oauth2UserInfo {
    String getProviderId();
    String getProvider();
    String getEmail();
    String getName();
}
