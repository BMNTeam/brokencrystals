export enum AuthType {
  FORM_BASED = 'application/x-www-form-urlencoded',
  APPLICATION_JSON = 'application/json'
}

export interface LoginUser {
  user: string;
  password: string;
  csrf?: string;
  op?: LoginFormMode;
}

export enum LoginFormMode {
  BASIC = 'basic',
  HTML = 'html',
  CSRF = 'csrf',
  OIDC_PASSWORD = 'oidc_password'
}

export type LoginFormModeKeys = typeof LoginFormMode[keyof typeof LoginFormMode] | string;

export interface LoginFormValue extends LoginUser {
  mode: LoginFormMode;
}

export interface LoginResponse {
  email: string;
  ldapProfileLink: string;
}

export interface RegistrationUser {
  email: string;
  lastName: string;
  firstName: string;
  password?: string;
}
