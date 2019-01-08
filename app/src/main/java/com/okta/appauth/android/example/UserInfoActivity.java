/*
 * Copyright (c) 2017, Okta, Inc. and/or its affiliates. All rights reserved.
 * The Okta software accompanied by this notice is provided pursuant to the Apache License,
 * Version 2.0 (the "License.")
 *
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the
 * License.
 */

package com.okta.appauth.android.example;

import android.app.PendingIntent;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.support.annotation.MainThread;
import android.support.annotation.NonNull;
import android.support.design.widget.Snackbar;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;

import com.bumptech.glide.Glide;
import com.okta.appauth.android.OktaAppAuth;
import net.openid.appauth.AuthorizationException;
import org.joda.time.format.DateTimeFormat;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.concurrent.atomic.AtomicReference;

import static com.okta.appauth.android.OktaAppAuth.getInstance;

/**
 * Example Activity that performs some authorized action. In this example, we show how to
 * get the user information from the
 * <a href="https://developer.okta.com/docs/api/resources/oidc.html#get-user-information">
 * userinfo endpoint</a> of Okta's OpenID Connect API.
 */
public class UserInfoActivity extends AppCompatActivity {

    private static final String TAG = "UserInfoActivity";

    private static final String KEY_USER_INFO = "userInfo";
    private static final String EXTRA_FAILED = "failed";

    private OktaAppAuth mOktaAppAuth;
    private final AtomicReference<JSONObject> mUserInfoJson = new AtomicReference<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        mOktaAppAuth = getInstance(this);
        setContentView(R.layout.activity_user_info);

        if (!mOktaAppAuth.isUserLoggedIn()) {
            Log.d(TAG, "No logged in user found. Finishing session");
            displayLoading("Finishing session");
            clearData();
            finish();
        }

        displayLoading(getString(R.string.loading_restoring));

        if (savedInstanceState != null) {
            try {
                mUserInfoJson.set(new JSONObject(savedInstanceState.getString(KEY_USER_INFO)));
            } catch (JSONException ex) {
                Log.e(TAG, "Failed to parse saved user info JSON, discarding", ex);
            }
        }
    }

    @Override
    protected void onStart() {
        super.onStart();

        if (mOktaAppAuth.isUserLoggedIn()) {
            displayAuthorizationInfo();
        } else {
            Log.i(TAG, "No authorization state retained - reauthorization required");
            startActivity(new Intent(this, LoginActivity.class));
            finish();
        }
    }

    @Override
    protected void onSaveInstanceState(Bundle state) {
        // user info is retained to survive activity restarts, such as when rotating the
        // device or switching apps. This isn't essential, but it helps provide a less
        // jarring UX when these events occur - data does not just disappear from the view.
        super.onSaveInstanceState(state);
        if (mUserInfoJson.get() != null) {
            state.putString(KEY_USER_INFO, mUserInfoJson.toString());
        }
    }

    /**
     * Demonstrates how to manually refresh the access token.
     */
    @MainThread
    private void refreshAccessToken() {
        displayLoading("Refreshing access token");
        mOktaAppAuth.refreshAccessToken(new OktaAppAuth.OktaAuthListener() {
            @Override
            public void onSuccess() {
                runOnUiThread(() -> displayAuthorizationInfo());
            }

            @Override
            public void onTokenFailure(@NonNull AuthorizationException ex) {
                runOnUiThread(() -> showSnackbar(getString(R.string.token_failure_message)));
            }
        });
    }

    /**
     * Demonstrates the use of {@link OktaAppAuth#getUserInfo(OktaAppAuth.OktaAuthActionCallback)}
     * to retrieve user info from the Okta's user info endpoint. This callback will negotiate a new
     * access token / ID token if possible, or provide an error if this fails.
     */
    @MainThread
    private void fetchUserInfo() {
        displayLoading(getString(R.string.user_info_loading));
        mOktaAppAuth.getUserInfo(new OktaAppAuth.OktaAuthActionCallback<JSONObject>() {
            @Override
            public void onSuccess(JSONObject response) {
                // Do whatever you need to do with the user info data
                mUserInfoJson.set(response);
                runOnUiThread(() -> displayAuthorizationInfo());
            }

            @Override
            public void onTokenFailure(@NonNull AuthorizationException ex) {
                // Handle an error with the Okta authorization and tokens
                mUserInfoJson.set(null);
                runOnUiThread(() -> {
                    displayAuthorizationInfo();
                    showSnackbar(getString(R.string.token_failure_message));
                });
            }

            @Override
            public void onFailure(int httpResponseCode, Exception ex) {
                // Handle a network error when fetching the user info data
                mUserInfoJson.set(null);
                runOnUiThread(() -> {
                    displayAuthorizationInfo();
                    showSnackbar(getString(R.string.network_failure_message));
                });
            }
        });
    }

    /**
     * Demonstrates signing out of your application.
     */
    @MainThread
    private void signOut() {
        displayLoading("Ending current session");
        Intent completionIntent = new Intent(this, LoginActivity.class);
        Intent cancelIntent = new Intent(this, UserInfoActivity.class);
        cancelIntent.putExtra(EXTRA_FAILED, true);
        cancelIntent.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP);
        completionIntent.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK);

        mOktaAppAuth.signOutFromOkta(this,
                PendingIntent.getActivity(this, 0, completionIntent, 0),
                PendingIntent.getActivity(this, 0, cancelIntent, 0)
        );

    }

    @MainThread
    private void clearData() {
        mOktaAppAuth.revoke(new OktaAppAuth.OktaRevokeListener() {
            @Override
            public void onSuccess() {
                mOktaAppAuth.clearSession();
                startActivity(new Intent(UserInfoActivity.this, LoginActivity.class));
                finish();
            }

            @Override
            public void onError(AuthorizationException ex) {
                showSnackbar("Unable to clean data");
            }
        });
    }

    @MainThread
    private void displayLoading(String message) {
        findViewById(R.id.loading_container).setVisibility(View.VISIBLE);
        findViewById(R.id.authorized).setVisibility(View.GONE);

        ((TextView) findViewById(R.id.loading_description)).setText(message);
    }

    /**
     * Displays information available from OktaAppAuth.
     */
    @MainThread
    private void displayAuthorizationInfo() {
        findViewById(R.id.authorized).setVisibility(View.VISIBLE);
        findViewById(R.id.loading_container).setVisibility(View.GONE);

        TextView refreshTokenInfoView = findViewById(R.id.refresh_token_info);
        refreshTokenInfoView.setText(!mOktaAppAuth.hasRefreshToken()
                ? R.string.no_refresh_token_returned
                : R.string.refresh_token_returned);

        TextView idTokenInfoView = findViewById(R.id.id_token_info);
        idTokenInfoView.setText(!mOktaAppAuth.hasIdToken()
                ? R.string.no_id_token_returned
                : R.string.id_token_returned);

        TextView accessTokenInfoView = findViewById(R.id.access_token_info);
        if (!mOktaAppAuth.hasAccessToken()) {
            accessTokenInfoView.setText(R.string.no_access_token_returned);
        } else {
            Long expiresAt = mOktaAppAuth.getAccessTokenExpirationTime();
            if (expiresAt == null) {
                accessTokenInfoView.setText(R.string.no_access_token_expiry);
            } else if (expiresAt < System.currentTimeMillis()) {
                accessTokenInfoView.setText(R.string.access_token_expired);
            } else {
                String template = getResources().getString(R.string.access_token_expires_at);
                accessTokenInfoView.setText(String.format(template,
                        DateTimeFormat.forPattern("yyyy-MM-dd HH:mm:ss ZZ").print(expiresAt)));
            }
        }

        Button refreshTokenButton = findViewById(R.id.refresh_token);
        refreshTokenButton.setVisibility(mOktaAppAuth.hasRefreshToken()
                ? View.VISIBLE
                : View.GONE);
        refreshTokenButton.setOnClickListener((View view) -> refreshAccessToken());

        Button viewProfileButton = findViewById(R.id.view_profile);

        viewProfileButton.setVisibility(View.VISIBLE);
        viewProfileButton.setOnClickListener((View view) -> fetchUserInfo());

        Button revokeTokenButton = findViewById(R.id.revoke_token);

        revokeTokenButton.setVisibility(View.VISIBLE);
        revokeTokenButton.setOnClickListener((View view) -> clearData());

        (findViewById(R.id.sign_out)).setOnClickListener((View view) -> signOut());

        View userInfoCard = findViewById(R.id.userinfo_card);
        JSONObject userInfo = mUserInfoJson.get();
        if (userInfo == null) {
            userInfoCard.setVisibility(View.INVISIBLE);
        } else {
            try {
                String name = "???";
                if (userInfo.has("name")) {
                    name = userInfo.getString("name");
                }
                ((TextView) findViewById(R.id.userinfo_name)).setText(name);

                if (userInfo.has("picture")) {
                    Glide.with(UserInfoActivity.this)
                            .load(Uri.parse(userInfo.getString("picture")))
                            .fitCenter()
                            .into((ImageView) findViewById(R.id.userinfo_profile));
                }

                ((TextView) findViewById(R.id.userinfo_json)).setText(mUserInfoJson.toString());
                userInfoCard.setVisibility(View.VISIBLE);
            } catch (JSONException ex) {
                Log.e(TAG, "Failed to read userinfo JSON", ex);
            }
        }
    }

    @MainThread
    private void showSnackbar(String message) {
        getWindow().getDecorView().post(() -> Snackbar.make(findViewById(R.id.coordinator),
                message,
                Snackbar.LENGTH_SHORT)
                .show());
    }
}
