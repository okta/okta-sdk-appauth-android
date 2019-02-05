package com.okta.auth;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.net.Uri;
import android.os.Handler;
import android.os.Looper;
import android.support.annotation.ColorInt;
import android.support.annotation.NonNull;
import android.support.annotation.WorkerThread;
import android.text.TextUtils;
import android.util.Log;

import com.okta.appauth.android.AuthenticationPayload;
import com.okta.auth.http.HttpRequest;
import com.okta.auth.http.HttpResponse;

import net.openid.appauth.AuthorizationException;
import net.openid.appauth.AuthorizationManagementResponse;
import net.openid.appauth.AuthorizationRequest;
import net.openid.appauth.AuthorizationResponse;
import net.openid.appauth.IdToken;
import net.openid.appauth.ResponseTypeValues;
import net.openid.appauth.SystemClock;
import net.openid.appauth.TokenRequest;
import net.openid.appauth.TokenResponse;
import net.openid.appauth.Utils;
import net.openid.appauth.connectivity.DefaultConnectionBuilder;
import net.openid.appauth.internal.Logger;
import net.openid.appauth.internal.UriUtil;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static android.app.Activity.RESULT_CANCELED;
import static com.okta.auth.OktaAuthenticationActivity.EXTRA_AUTH_URI;
import static com.okta.auth.OktaAuthenticationActivity.EXTRA_TAB_OPTIONS;

public final class OktaAuthManager {
    private static final String TAG = OktaAuthManager.class.getSimpleName();

    private enum AuthState {
        INIT, DISC, AUTH, CODE_EXCHANGE, FINISH
    }

    //login method. currently only NATIVE and BROWSER_TAB.
    public enum LoginMethod {
        BROWSER_TAB, NATIVE
    }

    private Activity mActivity;
    private OktaAuthAccount mOktaAuthAccount;
    private AuthorizationCallback mCallback;
    private AuthenticationPayload mPayload;
    private int mCustomTabColor;

    private ExecutorService mExecutor = Executors.newSingleThreadExecutor();

    //private OktaClientAPI mOktaClient;
    private AuthorizationRequest mAuthRequest;
    private AuthorizationResponse mAuthResponse;
    private LoginMethod mMethod;
    private AuthState mState;
    private Handler mMainHandler;
    private Runnable mCurrentRunnable;
    private static final int REQUEST_CODE = 100;

    private OktaAuthManager(@NonNull Builder builder) {
        mActivity = builder.mActivity;
        mOktaAuthAccount = builder.mOktaAuthAccount;
        mCallback = builder.mCallback;
        mCustomTabColor = builder.mCustomTabColor;
        mPayload = builder.mPayload;
        mMethod = builder.mMethod;
        mState = AuthState.INIT;
        mMainHandler = new Handler(Looper.getMainLooper());
    }

    //Send results back on main thread.
    private void deliverResults(Runnable r) {
        if (mCallback != null) {
            if (mCurrentRunnable != null) {
                mMainHandler.removeCallbacks(mCurrentRunnable);
            }
            mCurrentRunnable = r;
            mMainHandler.post(mCurrentRunnable);
        }
    }

    //https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
    public void startAuthorization() {
        if (!mOktaAuthAccount.isConfigured()) {
            mCallback.onStatus("configuration");
            mExecutor.submit(() -> {
                try {
                    mOktaAuthAccount.obtainConfiguration();
                    if (mMethod == LoginMethod.BROWSER_TAB && !isRedirectUrisRegistered(mOktaAuthAccount.getRedirectUri())) {
                        mCallback.onError("No uri registered to handle redirect", null);
                        return;
                    }
                    mState = AuthState.DISC;
                } catch (AuthorizationException ae) {
                    deliverResults(() -> mCallback.onError("", ae));
                }
            });
        }
        if (mMethod == LoginMethod.BROWSER_TAB) {
            mExecutor.submit(this::authenticate);
        } else if (mMethod == LoginMethod.NATIVE) {
            //TODO start native login flow.
        }
    }

    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode != REQUEST_CODE) {
            return;
        }
        if (resultCode == RESULT_CANCELED) {
            mCallback.onCancel();
            return;
        }

        Uri responseUri = data.getData();
        Intent responseData = extractResponseData(responseUri);
        if (responseData == null) {
            mCallback.onError("Failed to extract OAuth2 response from redirect",
                    AuthorizationException.GeneralErrors.INVALID_REGISTRATION_RESPONSE);
            return;
        }
        //TODO handle other response types.
        AuthorizationManagementResponse response =
                AuthorizationManagementResponse.fromIntent(responseData);
        AuthorizationException ex = AuthorizationException.fromIntent(responseData);

        if (ex != null || response == null) {
            mCallback.onError("Authorization flow failed: ", ex);
        } else if (response instanceof AuthorizationResponse) {
            mAuthResponse = (AuthorizationResponse) response;
            mState = AuthState.AUTH;
            mCallback.onStatus("Code exchange");
            mExecutor.submit(this::codeExchange);
        } else {
            mCallback.onCancel();
        }
    }

    public void onDestroy() {
        Log.d(TAG, "onDestroy called");
        if (mCurrentRunnable != null) {
            mMainHandler.removeCallbacks(mCurrentRunnable);
        }
        mCallback = null;
        mCurrentRunnable = null;
        mExecutor.shutdownNow();
    }

    @WorkerThread
    private void authenticate() {
        if (mOktaAuthAccount.isConfigured()) {
            mAuthRequest = createAuthRequest();
            Intent intent = createAuthIntent();
            mActivity.startActivityForResult(intent, REQUEST_CODE);
        } else {
            deliverResults(() -> mCallback.onError("Invalid account information",
                    AuthorizationException.GeneralErrors.INVALID_DISCOVERY_DOCUMENT));
        }
    }

    @WorkerThread
    private void codeExchange() {
        AuthorizationException exception;
        HttpResponse response = null;
        try {
            TokenRequest tokenRequest = mAuthResponse.createTokenExchangeRequest();
            Map<String, String> parameters = tokenRequest.getRequestParameters();
            parameters.put(TokenRequest.PARAM_CLIENT_ID, mAuthRequest.clientId);

            response = new HttpRequest.Builder().setRequestMethod(HttpRequest.RequestMethod.POST)
                    .setUri(mOktaAuthAccount.getServiceConfig().tokenEndpoint)
                    .setRequestProperty("Accept", "application/json")
                    .addPostParameters(parameters)
                    .create()
                    .executeRequest();

            JSONObject json = response.asJson();
            if (json.has(AuthorizationException.PARAM_ERROR)) {
                try {
                    final String error = json.getString(AuthorizationException.PARAM_ERROR);
                    final AuthorizationException ex = AuthorizationException.fromOAuthTemplate(
                            AuthorizationException.TokenRequestErrors.byString(error),
                            error,
                            json.optString(AuthorizationException.PARAM_ERROR_DESCRIPTION, null),
                            UriUtil.parseUriIfAvailable(
                                    json.optString(AuthorizationException.PARAM_ERROR_URI)));
                    deliverResults(() -> mCallback.onError(error, ex));
                } catch (JSONException jsonEx) {
                    AuthorizationException.fromTemplate(
                            AuthorizationException.GeneralErrors.JSON_DESERIALIZATION_ERROR,
                            jsonEx);
                    deliverResults(() -> mCallback.onError("error", AuthorizationException.fromTemplate(
                            AuthorizationException.GeneralErrors.JSON_DESERIALIZATION_ERROR,
                            jsonEx)));
                }
                return;
            }

            TokenResponse tokenResponse;
            try {
                tokenResponse = new TokenResponse.Builder(tokenRequest).fromResponseJson(json).build();
            } catch (JSONException jsonEx) {
                deliverResults(() -> mCallback.onError("JsonException", AuthorizationException.fromTemplate(
                        AuthorizationException.GeneralErrors.JSON_DESERIALIZATION_ERROR,
                        jsonEx)));
                return;
            }

            if (tokenResponse.idToken != null) {
                IdToken idToken;
                try {
                    idToken = IdToken.from(tokenResponse.idToken);
                } catch (IdToken.IdTokenException | JSONException ex) {
                    deliverResults(() -> mCallback.onError("Unable to parse ID Token",
                            AuthorizationException.fromTemplate(
                                    AuthorizationException.GeneralErrors.ID_TOKEN_PARSING_ERROR,
                                    ex)));
                    return;
                }

                try {
                    idToken.validate(tokenRequest, SystemClock.INSTANCE);
                } catch (AuthorizationException ex) {
                    deliverResults(() -> mCallback.onError("IdToken validation error", ex));
                    return;
                }
            }
            deliverResults(() -> mCallback.onSuccess(new OktaClientAPI(mOktaAuthAccount, tokenResponse)));
        } catch (IOException ex) {
            Logger.debugWithStack(ex, "Failed to complete exchange request");
            exception = AuthorizationException.fromTemplate(
                    AuthorizationException.GeneralErrors.NETWORK_ERROR, ex);
            deliverResults(() -> mCallback.onError("Failed to complete exchange request", exception));
        } catch (JSONException ex) {
            Logger.debugWithStack(ex, "Failed to complete exchange request");
            exception = AuthorizationException.fromTemplate(
                    AuthorizationException.GeneralErrors.JSON_DESERIALIZATION_ERROR, ex);
            deliverResults(() -> mCallback.onError("Failed to complete exchange request", exception));
        } finally {
            if (response != null) {
                response.disconnect();
            }
        }
    }

    private Intent createAuthIntent() {
        Intent intent = new Intent(mActivity, OktaAuthenticationActivity.class);
        intent.putExtra(EXTRA_AUTH_URI, mAuthRequest.toUri());
        intent.putExtra(EXTRA_TAB_OPTIONS, mCustomTabColor);
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
        return intent;
    }

    private boolean isRedirectUrisRegistered(@NonNull Uri uri) {
        PackageManager pm = mActivity.getPackageManager();
        List<ResolveInfo> resolveInfos = null;
        if (pm != null) {
            Intent intent = new Intent();
            intent.setAction(Intent.ACTION_VIEW);
            intent.addCategory(Intent.CATEGORY_BROWSABLE);
            intent.setData(uri);
            resolveInfos = pm.queryIntentActivities(intent, PackageManager.GET_RESOLVED_FILTER);
        }
        boolean found = false;
        if (resolveInfos != null) {
            for (ResolveInfo info : resolveInfos) {
                ActivityInfo activityInfo = info.activityInfo;
                if (activityInfo.name.equals(OktaRedirectActivity.class.getCanonicalName()) &&
                        activityInfo.packageName.equals(mActivity.getPackageName())) {
                    found = true;
                } else {
                    Log.w(TAG, "Warning! Multiple applications found registered with same scheme");
                    //Another installed app have same url scheme.
                    //return false as if no activity found to prevent hijacking of redirect.
                    return false;
                }
            }
        }
        return found;
    }

    private AuthorizationRequest createAuthRequest() {
        AuthorizationRequest.Builder authRequestBuilder = new AuthorizationRequest.Builder(
                mOktaAuthAccount.getServiceConfig(),
                mOktaAuthAccount.getClientId(),
                ResponseTypeValues.CODE,
                mOktaAuthAccount.getRedirectUri())
                .setScopes(mOktaAuthAccount.getScopes());

        if (mPayload != null) {
            authRequestBuilder.setAdditionalParameters(mPayload.getAdditionalParameters());
            if (!TextUtils.isEmpty(mPayload.toString())) {
                authRequestBuilder.setState(mPayload.getState());
            }
            if (!TextUtils.isEmpty(mPayload.getLoginHint())) {
                authRequestBuilder.setLoginHint(mPayload.getLoginHint());
            }
        }
        return authRequestBuilder.build();
    }

    private Intent extractResponseData(Uri responseUri) {
        if (responseUri.getQueryParameterNames().contains(AuthorizationException.PARAM_ERROR)) {
            return AuthorizationException.fromOAuthRedirect(responseUri).toIntent();
        } else {
            //TODO mAuthRequest is null if Activity is destroyed.
            if (mAuthRequest == null) {

            }
            AuthorizationManagementResponse response = AuthorizationManagementResponse
                    .buildFromRequest(mAuthRequest, responseUri);

            if (mAuthRequest.getState() == null && response.getState() != null
                    || (mAuthRequest.getState() != null && !mAuthRequest.getState()
                    .equals(response.getState()))) {

                Logger.warn("State returned in authorization response (%s) does not match state "
                                + "from request (%s) - discarding response",
                        response.getState(),
                        mAuthRequest.getState());

                return AuthorizationException.AuthorizationRequestErrors.STATE_MISMATCH.toIntent();
            }
            return response.toIntent();
        }
    }

    public static final class Builder {
        private Activity mActivity;
        private OktaAuthAccount mOktaAuthAccount;
        private AuthorizationCallback mCallback;
        private AuthenticationPayload mPayload;
        private int mCustomTabColor;
        private LoginMethod mMethod = LoginMethod.BROWSER_TAB;

        public Builder(@NonNull Activity activity) {
            mActivity = activity;
        }

        public OktaAuthManager create() {
            return new OktaAuthManager(this);
        }

        public Builder withCallback(@NonNull AuthorizationCallback callback) {
            mCallback = callback;
            return this;
        }

        public Builder withAccount(@NonNull OktaAuthAccount account) {
            mOktaAuthAccount = account;
            return this;
        }

        public Builder withPayload(@NonNull AuthenticationPayload payload) {
            mPayload = payload;
            return this;
        }

        public Builder withTabColor(@ColorInt int customTabColor) {
            mCustomTabColor = customTabColor;
            return this;
        }

        public Builder withMethod(@NonNull LoginMethod method) {
            mMethod = method;
            return this;
        }
    }
}