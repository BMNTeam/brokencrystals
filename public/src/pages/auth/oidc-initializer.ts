import Oidc, { SessionStatus, User, UserManagerSettings } from 'oidc-client';

Oidc.Log.logger = console;
Oidc.Log.level = Oidc.Log.INFO;

const userManagerConfig: UserManagerSettings = {
  authority: 'http://185.186.246.171:8080/auth/realms/master',
  client_id: '6fceb0d8-5ace-4535-b455-5b500f3a6d21',
  redirect_uri: 'http://localhost:3001',
  post_logout_redirect_uri: 'http://localhost:3001',

  response_type: 'id_token token',
  // scope: 'openid email roles',
  scope: 'openid email',

  popup_redirect_uri: 'http://localhost:3001/oidc/user-manager-sample-popup-signin.html',
  popup_post_logout_redirect_uri: 'http://localhost:3001/oidc/user-manager-sample-popup-signin.html',

  silent_redirect_uri: 'http://localhost:3001/oidc/user-manager-sample-silent.html',
  automaticSilentRenew: true,
  silentRequestTimeout: 10000,
  accessTokenExpiringNotificationTime: 60,
  revokeAccessTokenOnSignout: false,

  filterProtocolClaims: true,
  loadUserInfo: true
  // client_authentication: 'client_secret_post' // client_secret_basic
};

const userManager = new Oidc.UserManager(userManagerConfig);

userManager.events.addAccessTokenExpiring(function () {
  console.log('token expiring...');
});

// Raised when a user session has been established (or re-established).
userManager.events.addUserLoaded((...args) => {
  console.warn('addUserLoaded', args);
});
// Raised when a user session has been terminated.
userManager.events.addUserUnloaded((...args) => {
  console.warn('addUserUnloaded', args);
});
// Raised prior to the access token expiring.
userManager.events.addAccessTokenExpiring((...args) => {
  console.warn('addAccessTokenExpiring', args);
});
// Raised after the access token has expired.
userManager.events.addAccessTokenExpired((...args) => {
  console.warn('addAccessTokenExpired', args);
});
// Raised when the automatic silent renew has failed.
userManager.events.addSilentRenewError((...args) => {
  console.warn('addSilentRenewError', args);
});
// .9.0]: Raised when the user is signed in.
userManager.events.addUserSignedIn((...args) => {
  console.warn('addUserSignedIn', args);
});
// .1.0]: Raised when the user's sign-in status at the OP has changed.
userManager.events.addUserSignedOut((...args) => {
  console.warn('addUserSignedOut', args);
});
// Raised when the user session changed (when monitorSession is set)
userManager.events.addUserSessionChanged((...args) => {
  console.warn('addUserSessionChanged', args);
});

function signinRedirect({ state } = { state: 'some data' }): Promise<User | void> {
  return userManager
    .signinRedirect({ state })
    .then((user) => {
      log('signed in', user);
      return user;
    })
    .catch((err) => {
      log(err);
      throw err;
    });
}

function popupSignin({ state } = { state: 'some data' }): Promise<User | void> {
  return userManager
    .signinPopup({ state })
    .then((user) => {
      log('signed in', user);
      return user;
    })
    .catch((err) => {
      log(err);
      throw err;
    });
}

function popupSignout({ state } = { state: 'some data' }) {
  return userManager
    .signoutPopup({ state })
    .then(() => {
      log('signed out');
    })
    .catch((err) => {
      log(err);
      throw err;
    });
}

function iframeSignin({ state } = { state: 'some data' }): Promise<User | void> {
  return userManager
    .signinSilent({ state })
    .then((user) => {
      log('signed in', user);
      return user;
    })
    .catch((err) => {
      log(err);
      throw err;
    });
}

function querySessionStatus({ state } = { state: 'some data' }): Promise<SessionStatus | void> {
  return userManager
    .querySessionStatus({ state })
    .then((sessionStatus) => {
      log('signed in', sessionStatus);
      return sessionStatus;
    })
    .catch((err) => {
      log(err);
      throw err;
    });
}

function getUserInfo(): Promise<User | null | void> {
  return userManager
    .getUser()
    .then((user) => {
      log('has user:', user);

      return user;
    })
    .catch((err) => {
      log(err);
      throw err;
    });
}

function removeUser(): Promise<void> {
  return userManager
    .removeUser()
    .then(() => {
      log('user removed');
    })
    .catch((err) => {
      log(err);
      throw err;
    });
}

function clearStaleState(): Promise<void> {
  return userManager
    .clearStaleState()
    .then(() => {
      log('stale state cleared');
    })
    .catch((err) => {
      log(err);
      throw err;
    });
}

function setUser({ user }: { user: User }) {
  return userManager
    .storeUser(user)
    .then(() => {
      log('user stored:', user);
    })
    .catch((err) => {
      log(err);
      throw err;
    });
}

function log(...args: Array<string | Error | unknown>): void {
  args.forEach((msg) => {
    if (msg instanceof Error) {
      msg = `Error: ${msg.message}`;
    } else if (typeof msg !== 'string') {
      msg = JSON.stringify(msg, null, 2);
    }

    console.warn('[OIDC]:', msg);
  });
}

export {
  userManager,
  popupSignin,
  popupSignout,
  iframeSignin,
  querySessionStatus,
  getUserInfo,
  removeUser,
  clearStaleState,
  setUser,
  signinRedirect
};
