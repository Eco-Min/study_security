# study_security

Authentication (시큐리티 세션)
* UserDetails
* Oauth2User
<br>
-> 이 두값을 한번에 처리하기위해 PrincipalDetails 로 묶어서 해결   
```java
public class PrincipalDetails implements UserDetails, OAuth2User
```
## Oauth2-client
oauth2-client 들을 각 포탈마다 담아줄 수 없다.<br>
google, apple, twitter, facebook, github...<br>
-> getAttribute() 값들이 다르기 때문
