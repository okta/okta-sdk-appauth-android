package com.okta.auth;

import android.support.annotation.NonNull;
import android.support.annotation.WorkerThread;
import android.util.Log;

import com.okta.auth.http.HttpRequest;
import com.okta.auth.http.HttpResponse;

import net.openid.appauth.TokenResponse;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.net.MalformedURLException;

//Client API for a client that is already logged in (authenticated).
public class OktaClientAPI {
    private OktaAuthAccount mOktaAuthAccount;
    private TokenResponse mTokenResponse;

    OktaClientAPI(OktaAuthAccount account, TokenResponse response) {
        mOktaAuthAccount = account;
        mTokenResponse = response;
    }

    @WorkerThread
    public JSONObject getUserProfile() throws IOException, JSONException {
        HttpResponse response = new HttpRequest.Builder().setRequestMethod(HttpRequest.RequestMethod.POST)
                .setUri(mOktaAuthAccount.getServiceConfig().discoveryDoc.getUserinfoEndpoint())
                .setRequestProperty("Authorization", "Bearer " + mTokenResponse.accessToken)
                .create()
                .executeRequest();
        return response.asJson();
    }
}
