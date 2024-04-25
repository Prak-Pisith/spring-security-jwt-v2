package pisith.xyz.securityjwtv2.demo;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import pisith.xyz.securityjwtv2.users.User;

@RestController
@RequestMapping("/api/v1/demo")
public class DemoController {

    @GetMapping("")
    public ResponseEntity<String> sayHello() {
        return ResponseEntity.ok().body("Hello MF this is Demo for secure endpoint");
    }

    @GetMapping("/me")
    public ResponseEntity<User> authenticatedUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        var currentUser = (User) authentication.getPrincipal();
        return ResponseEntity.ok(currentUser);
    }
}
