package com.nqvinh.keycloak.service;

import com.nqvinh.keycloak.config.redis.SessionStorage;
import com.nqvinh.keycloak.dto.BaseResponseDTO;
import com.nqvinh.keycloak.dto.LoginRequestDTO;
import com.nqvinh.keycloak.dto.TokenDTO;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

@Slf4j
@Service
public class AuthService {

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private SessionStorage sessionStorage;

    @Value("${keycloak.client-id}")
    private String kcClientId;

    @Value("${keycloak.client-secret}")
    private String kcClientSecret;

    @Value("${keycloak.get-token-url}")
    private String kcGetTokenUrl;

    private static final String GRANT_TYPE_PASSWORD = "password";
    private static final String ACCESS_TOKEN = "Access-Token";
    private static final String REFRESH_TOKEN = "Refresh-Token";
    private static final String EXPIRES_IN = "Expires-In";
    private static final String DEVICE_ID = "Device-Id";

    public ResponseEntity<Object> login(LoginRequestDTO request, HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        log.info("Start to get access token");

        String deviceId = servletRequest.getHeader(DEVICE_ID);

        TokenDTO tokenDto = this.getAccessToken(request);

        servletResponse.addHeader(ACCESS_TOKEN, tokenDto.getAccessToken());
        servletResponse.addHeader(EXPIRES_IN, String.valueOf(tokenDto.getExpiresIn()));

        sessionStorage.putCache(REFRESH_TOKEN, deviceId, tokenDto.getRefreshToken(), 1800);

        return ResponseEntity.ok().body(BaseResponseDTO.builder()
                .status("SUCCESS")
                .build());
    }

    public ResponseEntity<Object> refreshToken(HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        log.info("Start to refresh access token");

        String deviceId = servletRequest.getHeader(DEVICE_ID);
        String refreshToken = (String) sessionStorage.getCache(REFRESH_TOKEN, deviceId);

        TokenDTO tokenDto = this.getRefreshToken(refreshToken);

        servletResponse.addHeader(ACCESS_TOKEN, tokenDto.getAccessToken());
        servletResponse.addHeader(EXPIRES_IN, String.valueOf(tokenDto.getExpiresIn()));

        sessionStorage.putCache(REFRESH_TOKEN, deviceId, tokenDto.getRefreshToken(), tokenDto.getRefreshExpiresIn());

        return ResponseEntity.ok().body(BaseResponseDTO.builder()
                .status("SUCCESS")
                .build());
    }

    private TokenDTO getAccessToken(LoginRequestDTO request) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
        requestBody.add("grant_type", GRANT_TYPE_PASSWORD);
        requestBody.add("client_id", kcClientId);
        requestBody.add("client_secret", kcClientSecret);
        requestBody.add("username", request.getUsername());
        requestBody.add("password", request.getPassword());

        ResponseEntity<TokenDTO> response = restTemplate.postForEntity(kcGetTokenUrl,
                new HttpEntity<>(requestBody, headers), TokenDTO.class);

        return response.getBody();
    }

    private TokenDTO getRefreshToken(String refreshToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
        requestBody.add("grant_type", "refresh_token");
        requestBody.add("refresh_token", refreshToken);
        requestBody.add("client_id", kcClientId);
        requestBody.add("client_secret", kcClientSecret);

        ResponseEntity<TokenDTO> response = restTemplate.postForEntity(kcGetTokenUrl,
                new HttpEntity<>(requestBody, headers), TokenDTO.class);

        return response.getBody();
    }
}