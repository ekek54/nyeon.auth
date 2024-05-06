package com.example.nyeon.auth.util;

import com.nimbusds.jose.shaded.gson.Gson;

/*
 * Gson is utilized for the serialization and deserialization of OAuth2AuthorizationRequest.
 * This is due to the fact that the default library, Jackson, does not support the deserialization of OAuth2AuthorizationRequest.
 */
public class SerializeUtil {
    private static final Gson gson = new Gson();

    public static String serialize(Object object) {
        return gson.toJson(object);
    }

    public static <T> T deserialize(String json, Class<T> clazz) {
        return gson.fromJson(json, clazz);
    }
}
