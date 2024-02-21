export const getAuth = jest.fn().mockReturnValue({});

export const signInWithCredential = jest.fn();

export const SignInMethod = {
  GOOGLE: "google.com",
};

export class OAuthProvider {
  credential() {
    return "test-credential";
  }
}
