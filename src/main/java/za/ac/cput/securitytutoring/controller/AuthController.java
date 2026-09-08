package za.ac.cput.securitytutoring.controller;


import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import za.ac.cput.securitytutoring.dto.AuthRequest;
import za.ac.cput.securitytutoring.dto.AuthResponse;
import za.ac.cput.securitytutoring.dto.RegisterRequest;
import za.ac.cput.securitytutoring.service.AuthService;

@RestController
@RequestMapping("/api/auth/v1")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/regiser")
    public ResponseEntity<AuthResponse> register(@RequestBody RegisterRequest registerRequest){
        AuthResponse resp = authService.register(registerRequest);
        return ResponseEntity.ok(resp);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> auth(@RequestBody AuthRequest authRequest){
        AuthResponse resp = authService.login(authRequest);
        System.out.println(resp.token());
        return ResponseEntity.ok(resp);
    }
}
