package com.repositorio.mvp.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.stereotype.Component;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

@Component
@Converter
public class MfaSecretConverter implements AttributeConverter<String, String> {

    private static TextEncryptor encryptor;

    public void setEncryptor(
            //injeta a chave e o salt do application properties
            @Value("${api.security.db.encryption.key}") String encryptionKey,
            @Value("${api.security.db.encryption.salt}") String saltHex){

        // Inicializa o encryptor com a chave e o salt
        MfaSecretConverter.encryptor = Encryptors.text(encryptionKey, saltHex);
    }
    //TODO adicionar um tratamento para caso de falha na despitografia ou criptografia
    @Override
    public String convertToDatabaseColumn(String attribute) {
        if (attribute == null) return null;
        return encryptor.encrypt(attribute); 
    }

    @Override
    public String convertToEntityAttribute(String dbData) {
        if (dbData == null) return null;
        return encryptor.decrypt(dbData);
    }

}
