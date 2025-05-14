export const getAuth = jest.fn().mockReturnValue({});

export const signInWithCredential = jest.fn();

export const ProviderId = {
  GOOGLE: "google.com",
  PASSWORD: "password",
};

export class OAuthProvider {
  credential() {
    return "test-credential";
  }
}
