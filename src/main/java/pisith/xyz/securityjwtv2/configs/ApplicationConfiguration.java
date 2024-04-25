package pisith.xyz.securityjwtv2.configs;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import pisith.xyz.securityjwtv2.users.UserRepository;

// To Override the UserDetailsService
// for fetching User from our own Datasource

@Configuration
@RequiredArgsConstructor
public class ApplicationConfiguration {

    private final UserRepository userRepository;

    @Bean
    public UserDetailsService userDetailsService() {
        return (UserDetailsService) username -> userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("Username Not Found"));
    }
}
