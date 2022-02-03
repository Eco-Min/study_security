package hello.security.model;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.*;

class UserTest {

    @Test
    public void userRoleTest() {
        User user = new User();
        user.setRole(Role.ROLE_USER);
        assertThat(user.getRole().toString()).isEqualTo("ROLE_USER");
    }
}