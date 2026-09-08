package za.ac.cput.securitytutoring.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** job is to see how secured endpoints would behave - returns a 403 forbidden */

@RequiredArgsConstructor
@RestController("/business-logic")
public class DummyController {
    @GetMapping("/hello")
    public String hello(){
        return "Hello Security ! ";
    }
}
