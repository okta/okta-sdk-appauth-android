package com.okta.auth;

import android.support.annotation.NonNull;
import android.support.annotation.WorkerThread;
import android.util.Log;

import net.openid.appauth.AuthorizationException;
import net.openid.appauth.AuthorizationResponse;
import net.openid.appauth.AuthorizationService;
import net.openid.appauth.ClientAuthentication;
import net.openid.appauth.TokenRequest;
import net.openid.appauth.TokenResponse;
import net.openid.appauth.internal.Logger;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;

import okio.Okio;

//Client API for a client that is already logged in (authenticated).
public class OktaClientAPI {
    private OktaAuthAccount mOktaAuthAccount;
    private TokenResponse mTokenResponse;

    OktaClientAPI(OktaAuthAccount account, TokenResponse response) {
        mOktaAuthAccount = account;
        mTokenResponse = response;
    }

    @WorkerThread
    public JSONObject getUserProfile() throws IOException, MalformedURLException, JSONException {
        URL userInfoEndpoint;
        userInfoEndpoint = new URL(mOktaAuthAccount.getServiceConfig().discoveryDoc.getUserinfoEndpoint().toString());
        String response;
        HttpURLConnection conn =
                (HttpURLConnection) userInfoEndpoint.openConnection();
        conn.setRequestProperty("Authorization", "Bearer " + mTokenResponse.accessToken);
        conn.setInstanceFollowRedirects(false);
        response = Okio.buffer(Okio.source(conn.getInputStream()))
                .readString(Charset.forName("UTF-8"));

        JSONObject jsonObject = new JSONObject(response);
        return jsonObject;
    }
}
