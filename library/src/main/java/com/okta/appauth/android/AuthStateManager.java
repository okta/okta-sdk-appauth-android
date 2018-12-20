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

package com.okta.appauth.android;

import android.content.Context;
import android.content.SharedPreferences;
import android.support.annotation.AnyThread;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.annotation.VisibleForTesting;
import android.util.Log;

import net.openid.appauth.AuthState;
import net.openid.appauth.AuthorizationException;
import net.openid.appauth.AuthorizationResponse;
import net.openid.appauth.TokenResponse;
import org.json.JSONException;

import java.lang.ref.WeakReference;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;

/**
 * A Manager for the Okta Authentication State. Handles the underlying {@link AuthState} from
 * the AppAuth library and stores it inside of {@link SharedPreferences}.
 */
@SuppressWarnings("WeakerAccess")
public class AuthStateManager {

    private static final String TAG = "AuthStateManager";

    private static final AtomicReference<WeakReference<AuthStateManager>> INSTANCE_REF =
            new AtomicReference<>(new WeakReference<AuthStateManager>(null));

    @VisibleForTesting
    static final String PREFS_NAME = "OktaAppAuthState";
    @VisibleForTesting
    static final String KEY_STATE = "state";

    private final SharedPreferences mPrefs;
    private final ReentrantLock mPrefsLock;
    private final AtomicReference<AuthState> mCurrentAuthState;

    /**
     * Retrieve the manager object via the static {@link WeakReference} or construct a new instance.
     * Stores the state in the {@link SharedPreferences} that we get from the
     * {@link Context#getSharedPreferences(String, int)} in {@link Context#MODE_PRIVATE}.
     *
     * @param context The Context from which to get the application's environment
     * @return an AuthStateManager object
     */
    @AnyThread
    public static AuthStateManager getInstance(@NonNull Context context) {
        AuthStateManager manager = INSTANCE_REF.get().get();
        if (manager == null) {
            manager = new AuthStateManager(
                    context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE),
                    new ReentrantLock()
            );
        }

        return manager;
    }

    @VisibleForTesting
    AuthStateManager(SharedPreferences prefs, ReentrantLock prefsLock) {
        mPrefs = prefs;
        mPrefsLock = prefsLock;
        mCurrentAuthState = new AtomicReference<>();

        INSTANCE_REF.set(new WeakReference<>(this));
    }

    /**
     * Returns the current AuthState stored in the {@link SharedPreferences}.
     *
     * @return the stored AuthState
     */
    @AnyThread
    @NonNull
    public AuthState getCurrent() {
        if (mCurrentAuthState.get() != null) {
            return mCurrentAuthState.get();
        }

        AuthState state = readState();
        if (mCurrentAuthState.compareAndSet(null, state)) {
            return state;
        } else {
            return mCurrentAuthState.get();
        }
    }

    /**
     * Replaces the current AuthState in {@link SharedPreferences} with the provided once.
     *
     * @param state The updated AuthState
     * @return The AuthState which was stored in the SharedPreferences
     */
    @AnyThread
    @NonNull
    public AuthState replace(@NonNull AuthState state) {
        writeState(state);
        mCurrentAuthState.set(state);
        return state;
    }

    /**
     * Called after the app receives the callback from the authorization code flow. This updates
     * the state to prepare for the token exchange.
     *
     * @param response The AuthorizationResponse from the Authorization Server
     * @param ex Any AuthorizationException that occurred during the authorization code flow
     * @return The updated AuthState
     */
    @AnyThread
    @NonNull
    public AuthState updateAfterAuthorization(
            @Nullable AuthorizationResponse response,
            @Nullable AuthorizationException ex) {
        AuthState current = getCurrent();
        current.update(response, ex);
        return replace(current);
    }

    /**
     * Called after the token exchange is complete or a refresh token is used to acquire a new
     * access token.
     *
     * @param response The TokenResponse from the Authorization Server
     * @param ex Any AuthorizationException that occurred during the token exchange
     * @return The updated AuthState
     */
    @AnyThread
    @NonNull
    public AuthState updateAfterTokenResponse(
            @Nullable TokenResponse response,
            @Nullable AuthorizationException ex) {
        AuthState current = getCurrent();
        current.update(response, ex);
        return replace(current);
    }

    @AnyThread
    @NonNull
    @VisibleForTesting
    AuthState readState() {
        mPrefsLock.lock();
        try {
            String currentState = mPrefs.getString(KEY_STATE, null);
            if (currentState == null) {
                return new AuthState();
            }

            try {
                return AuthState.jsonDeserialize(currentState);
            } catch (JSONException ex) {
                Log.w(TAG, "Failed to deserialize stored auth state - discarding");
                return new AuthState();
            }
        } finally {
            mPrefsLock.unlock();
        }
    }

    @AnyThread
    @VisibleForTesting
    void writeState(@Nullable AuthState state) {
        mPrefsLock.lock();
        try {
            SharedPreferences.Editor editor = mPrefs.edit();
            if (state == null) {
                editor.remove(KEY_STATE);
            } else {
                editor.putString(KEY_STATE, state.jsonSerializeString());
            }

            if (!editor.commit()) {
                throw new IllegalStateException("Failed to write state to shared prefs");
            }
        } finally {
            mPrefsLock.unlock();
        }
    }
}
