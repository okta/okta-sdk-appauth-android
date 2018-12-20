package com.okta;

import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import org.json.JSONException;
import org.json.JSONObject;

import static net.openid.appauth.Preconditions.checkNotNull;

public class JsonUtil {

    public static void put(
            @NonNull JSONObject json,
            @NonNull String field,
            @NonNull String value) {
        checkNotNull(json, "json must not be null");
        checkNotNull(field, "field must not be null");
        checkNotNull(value, "value must not be null");

        try {
            json.put(field, value);
        } catch (JSONException ex) {
            throw new IllegalStateException("JSONException thrown in violation of contract, ex");
        }
    }

    public static void putIfNotNull(
            @NonNull JSONObject json,
            @NonNull String field,
            @Nullable String value) {
        checkNotNull(json, "json must not be null");
        checkNotNull(field, "field must not be null");
        if (value == null) {
            return;
        }
        try {
            json.put(field, value);
        } catch (JSONException ex) {
            throw new IllegalStateException("JSONException thrown in violation of contract", ex);
        }
    }
}
