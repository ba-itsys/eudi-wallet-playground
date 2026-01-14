/*
 * Copyright 2026 Bundesagentur für Arbeit
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.arbeitsagentur.keycloak.wallet.common.util;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.util.Base64;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.List;

/**
 * Utility class for X.509 certificate operations.
 * Handles PEM parsing, JWK conversion, and certificate hashing.
 */
public final class CertificateUtils {

    private CertificateUtils() {
        // Utility class
    }

    /**
     * Parse a PEM-encoded X.509 certificate.
     *
     * @param pem the PEM-encoded certificate string
     * @return the parsed X509Certificate
     * @throws Exception if parsing fails
     */
    public static X509Certificate parsePemCertificate(String pem) throws Exception {
        if (pem == null || pem.isBlank()) {
            throw new IllegalArgumentException("PEM certificate string is null or empty");
        }
        String base64 = pem.trim()
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s+", "");
        byte[] der = java.util.Base64.getDecoder().decode(base64);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der));
    }

    /**
     * Parse a Base64-encoded X.509 certificate (DER format).
     *
     * @param base64Der the Base64-encoded DER certificate
     * @return the parsed X509Certificate
     * @throws Exception if parsing fails
     */
    public static X509Certificate parseBase64DerCertificate(String base64Der) throws Exception {
        if (base64Der == null || base64Der.isBlank()) {
            throw new IllegalArgumentException("Base64 certificate string is null or empty");
        }
        byte[] der = java.util.Base64.getDecoder().decode(base64Der.trim());
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der));
    }

    /**
     * Convert an X.509 certificate to PEM format.
     *
     * @param certificate the certificate to convert
     * @return the PEM-encoded certificate string
     * @throws Exception if conversion fails
     */
    public static String toPem(X509Certificate certificate) throws Exception {
        if (certificate == null) {
            throw new IllegalArgumentException("Certificate is null");
        }
        String base64 = java.util.Base64.getEncoder().encodeToString(certificate.getEncoded());
        StringBuilder pem = new StringBuilder();
        pem.append("-----BEGIN CERTIFICATE-----\n");
        for (int i = 0; i < base64.length(); i += 64) {
            pem.append(base64, i, Math.min(i + 64, base64.length()));
            pem.append("\n");
        }
        pem.append("-----END CERTIFICATE-----");
        return pem.toString();
    }

    /**
     * Compute the SHA-256 hash of a certificate's DER encoding.
     * Returns the hash as a URL-safe Base64 string without padding.
     *
     * @param certificate the certificate to hash
     * @return the Base64url-encoded SHA-256 hash
     * @throws Exception if hashing fails
     */
    public static String sha256Hash(X509Certificate certificate) throws Exception {
        if (certificate == null) {
            throw new IllegalArgumentException("Certificate is null");
        }
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(certificate.getEncoded());
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
    }

    /**
     * Convert an EC certificate's public key to a JWK JSON string.
     * Includes the certificate in the x5c claim.
     *
     * @param certificate the EC certificate
     * @return the JWK JSON string, or null if not an EC certificate
     */
    public static String toEcJwkJson(X509Certificate certificate) {
        if (certificate == null) {
            return null;
        }
        try {
            PublicKey publicKey = certificate.getPublicKey();
            if (!(publicKey instanceof ECPublicKey ecKey)) {
                return null;
            }

            java.security.spec.ECPoint w = ecKey.getW();
            byte[] xBytes = toUnsignedBytes(w.getAffineX(), 32);
            byte[] yBytes = toUnsignedBytes(w.getAffineY(), 32);
            String x = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(xBytes);
            String y = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(yBytes);
            String certBase64 = java.util.Base64.getEncoder().encodeToString(certificate.getEncoded());

            return "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + x + "\",\"y\":\"" + y
                    + "\",\"use\":\"sig\",\"x5c\":[\"" + certBase64 + "\"]}";
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Convert an EC certificate's public key to a JWK object.
     *
     * @param certificate the EC certificate
     * @return the ECKey JWK, or null if not an EC certificate
     */
    public static ECKey toEcJwk(X509Certificate certificate) {
        if (certificate == null) {
            return null;
        }
        try {
            PublicKey publicKey = certificate.getPublicKey();
            if (!(publicKey instanceof ECPublicKey)) {
                return null;
            }
            Base64 certBase64 = Base64.encode(certificate.getEncoded());
            return new ECKey.Builder(Curve.P_256, (ECPublicKey) publicKey)
                    .keyUse(KeyUse.SIGNATURE)
                    .x509CertChain(List.of(certBase64))
                    .build();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Extract the first DNS Subject Alternative Name from a certificate.
     *
     * @param certificate the certificate
     * @return the first DNS SAN, or null if not present
     */
    public static String firstDnsSan(X509Certificate certificate) {
        if (certificate == null) {
            return null;
        }
        try {
            var sans = certificate.getSubjectAlternativeNames();
            if (sans == null) {
                return null;
            }
            for (var san : sans) {
                // GeneralName type 2 = dNSName
                if (san.size() >= 2 && Integer.valueOf(2).equals(san.get(0))) {
                    Object value = san.get(1);
                    if (value instanceof String str && !str.isBlank()) {
                        return str;
                    }
                }
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Check if a certificate is self-signed.
     *
     * @param certificate the certificate to check
     * @return true if the certificate is self-signed
     */
    public static boolean isSelfSigned(X509Certificate certificate) {
        if (certificate == null) {
            return false;
        }
        try {
            certificate.verify(certificate.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Convert a BigInteger to an unsigned byte array with fixed length.
     * Used for EC coordinate encoding.
     *
     * @param value the BigInteger value
     * @param length the desired byte array length
     * @return the byte array
     */
    public static byte[] toUnsignedBytes(BigInteger value, int length) {
        byte[] bytes = value.toByteArray();
        if (bytes.length == length) {
            return bytes;
        }
        if (bytes.length == length + 1 && bytes[0] == 0) {
            // Strip leading zero byte (sign byte)
            byte[] result = new byte[length];
            System.arraycopy(bytes, 1, result, 0, length);
            return result;
        }
        if (bytes.length < length) {
            // Pad with leading zeros
            byte[] result = new byte[length];
            System.arraycopy(bytes, 0, result, length - bytes.length, bytes.length);
            return result;
        }
        return bytes;
    }
}
