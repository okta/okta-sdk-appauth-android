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

import com.okta.openid.appauth.AuthState;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;

import java.util.concurrent.locks.ReentrantLock;

import static com.okta.appauth.android.AuthStateManager.KEY_STATE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

@RunWith(RobolectricTestRunner.class)
public class AuthStateManagerTest {

    private SharedPreferences mPrefs;
    private ReentrantLock mPrefsLock;

    private AuthStateManager sut;

    @Before
    public void setUp() throws Exception {
        mPrefs = RuntimeEnvironment.application
                .getSharedPreferences(AuthStateManager.PREFS_NAME, Context.MODE_PRIVATE);
        mPrefsLock = new ThrowingReentrantLock();

        sut = new AuthStateManager(mPrefs, mPrefsLock);
    }

    @Test
    public void testGetInstanceUsesSameInstance() {
        assertThat(sut).isSameAs(AuthStateManager.getInstance(
                RuntimeEnvironment.application.getApplicationContext()));
        assertThat(sut.getCurrent().getAuthorizationServiceConfiguration()).isNull();
    }

    @Test
    public void testGetCurrentCachesState() {
        AuthState state = sut.getCurrent();
        assertThat(sut.getCurrent()).isSameAs(state);
        assertThat(mPrefs.contains(KEY_STATE)).isFalse();
    }

    @Test
    public void testReadStateLocksPreferencesBeforeActing() {
        assertThat(mPrefs.contains(KEY_STATE)).isFalse();

        mPrefsLock.lock();
        try {
            sut.readState();
            fail("Expected " + IllegalStateException.class.getSimpleName() + " to be thrown");
        } catch (IllegalStateException e) {
            assertThat(mPrefsLock.getHoldCount()).isEqualTo(1);
        }

        mPrefsLock.unlock();
        assertThat(sut.readState()).isNotNull();
        assertThat(mPrefsLock.getHoldCount()).isEqualTo(0);
        assertThat(mPrefs.contains(KEY_STATE)).isFalse();
    }

    @Test
    public void testWriteStateLocksPreferencesBeforeActing() {
        assertThat(mPrefs.contains(KEY_STATE)).isFalse();

        mPrefsLock.lock();
        try {
            sut.writeState(new AuthState());
            fail("Expected " + IllegalStateException.class.getSimpleName() + " to be thrown");
        } catch (IllegalStateException e) {
            assertThat(mPrefsLock.getHoldCount()).isEqualTo(1);
            assertThat(mPrefs.contains(KEY_STATE)).isFalse();
        }

        mPrefsLock.unlock();
        sut.writeState(new AuthState());
        assertThat(mPrefsLock.getHoldCount()).isEqualTo(0);
        assertThat(mPrefs.getString(KEY_STATE, null)).isNotNull();
    }

    @Test
    public void testWriteStateRemovesKeyWhenWritingNull() {
        sut.writeState(new AuthState());
        assertThat(mPrefs.getString(KEY_STATE, null)).isNotNull();

        sut.writeState(null);
        assertThat(mPrefs.contains(KEY_STATE)).isFalse();
    }

    private static class ThrowingReentrantLock extends ReentrantLock {
        @Override
        public void lock() {
            if (Thread.currentThread().equals(getOwner())) {
                throw new IllegalStateException("Owner trying to re-enter");
            } else {
                super.lock();
            }
        }
    }
}