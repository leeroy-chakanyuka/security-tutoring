package za.ac.cput.securitytutoring.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import za.ac.cput.securitytutoring.dto.AuthRequest;
import za.ac.cput.securitytutoring.dto.AuthResponse;
import za.ac.cput.securitytutoring.dto.RegisterRequest;
import za.ac.cput.securitytutoring.model.Role;
import za.ac.cput.securitytutoring.model.User;
import za.ac.cput.securitytutoring.repository.UserRepository;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final JwtService jwtService;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authManager;

    public AuthResponse register(RegisterRequest request){
        /* we assume all the data validation and cleaning has been done at this point (a lot of it would be handled on db / model anyway) */

        // 1. Save the new User to the db
        User newUser =  User.builder()
                .user(request.username())
                .pwd(passwordEncoder.encode(request.password())) /* always add the password hashed */
                .firstName(request.firstName())
                .lastName(request.lastName())
                .role(Role.USER)
                .build();

        userRepository.save(newUser);

        // 2. Generate a new token for them

        String token = jwtService.generateToken(newUser);

        return new AuthResponse(token);
    }

    public AuthResponse login(AuthRequest authRequest) {
        System.out.println("Login attempt for username: " + authRequest.username());

        try {
            authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(authRequest.username(), authRequest.password())
            );
            System.out.println("Authentication succeeded");
        } catch (Exception e) {
            System.out.println("Authentication FAILED: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            throw e; // rethrow so behavior doesn't silently change
        }

        // 2. check for the user on the db
        User user = userRepository.findByUser(authRequest.username())
                .orElseThrow(() -> {
                    System.out.println("User not found in DB after successful auth (shouldn't happen)");
                    return new RuntimeException("User not found");
                });

        System.out.println("User found: " + user.getUsername());

        // 3. return the right token
        String token = jwtService.generateToken(user);
        System.out.println("Token generated: " + token);

        return new AuthResponse(token);
    }
}
