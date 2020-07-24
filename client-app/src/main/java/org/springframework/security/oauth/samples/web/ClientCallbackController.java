package org.springframework.security.oauth.samples.web;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;

@RestController

public class ClientCallbackController {

    @Autowired
    RestTemplate restTemplate;

    @RequestMapping("/client/account/redirect")
    public String getToken(@RequestParam String code) {
        System.out.println("receive code {}"+code);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type", "authorization_code");
        params.add("code", code);
        params.add("client_id", "messaging-client");
        params.add("client_secret", "secret");
        params.add("redirect_uri", "http://localhost:8080/client/account/redirect");
        HttpEntity<MultiValueMap<String, String>> requestEntity = new HttpEntity<>(params, headers);
        ResponseEntity<String> response = restTemplate.postForEntity("http://localhost:8090/oauth2/token", requestEntity, String.class);
        String token = response.getBody();
        System.out.println("token => {}"+token);
        return token;
    }

    @RequestMapping("/client/account/aa")
    @ResponseBody
    public String getAA(HttpServletRequest request) {
        return "aa";
    }
}

