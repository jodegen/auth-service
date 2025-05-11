package de.jodegen.auth.rest.dto;

public record TokenPairResponse(String accessToken, String refreshToken) {
}
