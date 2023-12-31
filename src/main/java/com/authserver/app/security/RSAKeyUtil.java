package com.authserver.app.security;

import com.nimbusds.jose.jwk.RSAKey;
import jakarta.annotation.PostConstruct;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Component
public class RSAKeyUtil {

    private RSAKey key;

    public RSAKey getKey() {
        return key;
    }

    @PostConstruct
    @Async
    @Scheduled(fixedRateString = "PT1H")
    void generateKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);

            KeyPair keypair = generator.generateKeyPair();

            RSAPublicKey publicKey = (RSAPublicKey) keypair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) keypair.getPrivate();

            this.key = new RSAKey
                    .Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(UUID.randomUUID().toString())
                    .build();

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }


}
