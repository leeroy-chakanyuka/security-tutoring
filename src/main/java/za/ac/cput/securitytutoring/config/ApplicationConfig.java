package za.ac.cput.securitytutoring.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import za.ac.cput.securitytutoring.repository.UserRepository;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

    public final UserRepository userRepository;
    @Bean
    public UserDetailsService userDetailsService(){
        /* the user details service provides a method called loadByUserName which we then have to override for our
         * usecase - look up on the db to see if this user exist- we will be using lambdas moving on though
         */
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                return userRepository.findByUser(username)
                        .orElseThrow(() -> new UsernameNotFoundException("User not found on database"));
            }
        };
    }
}
