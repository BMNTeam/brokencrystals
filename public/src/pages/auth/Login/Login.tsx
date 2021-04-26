import { AxiosRequestConfig } from 'axios';
import React, { FC, FormEvent, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { getLdap, getUser, loadXsrfToken } from '../../../api/httpClient';
import {
  AuthType,
  LoginFormMode,
  LoginFormModeKeys,
  LoginFormValue,
  LoginResponse,
  LoginUser,
  RegistrationUser
} from '../../../interfaces/User';
import AuthLayout from '../AuthLayout';
import showLdapResponse from './showLdapReponse';
import showLoginResponse from './showLoginReponse';
import { userManager, querySessionStatus, getUserInfo, popupSignin, signinRedirect } from '../oidc-initializer';

const defaultLoginUser: LoginUser = {
  user: '',
  password: '',
  op: LoginFormMode.BASIC
};

const defaultFormValue: LoginFormValue = {
  ...defaultLoginUser,
  mode: LoginFormMode.BASIC
};

const formModeOptions: Record<LoginFormModeKeys, string> = {
  [LoginFormMode.BASIC]: 'Simple REST-based Authentication',
  [LoginFormMode.HTML]: 'Simple HTML Form-based Authentication',
  [LoginFormMode.CSRF]: 'Simple CSRF-based Authentication',
  [LoginFormMode.OIDC_PASSWORD]: 'Simple password-based OIDC'
};

export const Login: FC = () => {
  console.warn('userManager', userManager);

  const [form, setForm] = useState<LoginFormValue>(defaultFormValue);
  const { user, password } = form;

  const [loginResponse, setLoginResponse] = useState<LoginResponse | null>();
  const [ldapResponse, setLdapResponse] = useState<Array<RegistrationUser>>([]);

  const [mode, setMode] = useState<LoginFormMode>(LoginFormMode.BASIC);
  const [csrf, setCsrf] = useState<string>();

  const onInput = ({ target }: { target: EventTarget | null }) => {
    const { name, value } = target as HTMLInputElement;
    setForm({ ...form, [name]: value });
  };

  const onSelectMode = ({ target }: { target: EventTarget | null }) => {
    const { value } = target as HTMLSelectElement & { value: LoginFormMode };
    setForm({ ...form, op: value });
    setMode(value);
    switch (value as LoginFormMode) {
      default:
        return;
    }
  };

  const onFormSubmit = (e: FormEvent) => {
    e.preventDefault();
    const config: Pick<AxiosRequestConfig, 'headers'> =
      mode === LoginFormMode.HTML ? { headers: { 'content-type': AuthType.FORM_BASED } } : {};
    const params = appendParams(form);

    console.warn('mode', mode);

    switch (mode) {
      case LoginFormMode.HTML:
      case LoginFormMode.CSRF:
      case LoginFormMode.BASIC: {
        getUser(params, config)
          .then((data: LoginResponse) => {
            setLoginResponse(data);
            return data.email;
          })
          .then((email) => sessionStorage.setItem('email', email));
        break;
      }
      case LoginFormMode.OIDC_PASSWORD: {
        signinRedirect({ state: params.password })
          .then((user) => {
            console.warn('popup authorized', user);
          })
          .catch((err) => {
            console.warn('popup not authorized', err);
          });
      }
    }
  };

  const sendLdap = () => {
    const { ldapProfileLink } = loginResponse || {};
    ldapProfileLink &&
      getLdap(ldapProfileLink)
        .then((data) => setLdapResponse(data))
        .then(() => {
          window.location.href = '/';
        });
  };

  const appendParams = (data: LoginUser): LoginUser => {
    switch (mode) {
      case LoginFormMode.CSRF:
        return { ...data, csrf };
      default:
        return data;
    }
  };

  const loadCsrf = () => {
    loadXsrfToken().then((token) => setCsrf(token));
  };

  useEffect(() => sendLdap(), [loginResponse]);
  useEffect(() => {
    switch (mode) {
      case LoginFormMode.CSRF: {
        return loadCsrf();
      }
    }
  }, [mode]);

  const checkOidcSession = () =>
    querySessionStatus()
      .then((sessionStatus) => {
        console.warn('session status', sessionStatus);
        if (!sessionStatus) {
          throw new Error('no session');
        }

        return getUserInfo();
      })
      .then((user) => {
        console.warn('authorized', user);
      })
      .catch((err) => {
        console.warn('not authorized', err);
        console.warn('starting popup');

        return popupSignin();
      })
      .then((user) => {
        console.warn('popup authorized', user);
      })
      .catch((err) => {
        console.warn('popup not authorized', err);
      });

  return (
    <AuthLayout>
      <div className="login-form">
        <form onSubmit={onFormSubmit}>
          <div className="form-group">
            <label>Authentication Type</label>
            <select className="form-control" name="op" placeholder="Authentication Type" value={mode} onChange={onSelectMode}>
              {Object.keys(formModeOptions).map((key: LoginFormModeKeys) => (
                <option value={key} key={key}>
                  {formModeOptions[key]}
                </option>
              ))}
            </select>
          </div>

          {mode === LoginFormMode.OIDC_PASSWORD && (
            <div>
              <button onClick={checkOidcSession}>check oidc session</button>
            </div>
          )}

          <div className="form-group">
            <label>Email</label>
            <input className="au-input au-input--full" type="text" name="user" placeholder="Email" value={user} onInput={onInput} />
          </div>

          <div className="form-group">
            <label>Password</label>
            <input
              className="au-input au-input--full"
              type="password"
              name="password"
              placeholder="Password"
              value={password}
              onInput={onInput}
            />
          </div>
          {mode === LoginFormMode.CSRF && csrf && <input name="xsrf" type="hidden" value={csrf} />}

          {loginResponse && showLoginResponse(loginResponse)}
          <br />
          {ldapResponse && showLdapResponse(ldapResponse)}

          <button className="au-btn au-btn--block au-btn--green m-b-20" type="submit">
            sign in
          </button>
        </form>

        <div className="register-link">
          <p>
            Don't you have account? <Link to="/register">Sign Up Here</Link>
          </p>
        </div>
      </div>
    </AuthLayout>
  );
};

export default Login;
