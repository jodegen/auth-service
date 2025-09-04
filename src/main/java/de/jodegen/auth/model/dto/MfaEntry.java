package de.jodegen.auth.model.dto;

import java.time.Instant;

public record MfaEntry(String code, Instant expiresAt) {
}
