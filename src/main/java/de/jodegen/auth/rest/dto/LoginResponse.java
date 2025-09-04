package de.jodegen.auth.rest.dto;

public record LoginResponse(boolean twoFactorRequired, String pendingToken,
                            String accessToken, String refreshToken) {
}
