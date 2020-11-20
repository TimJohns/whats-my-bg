import {v1, SecretManagerServiceClient} from "@google-cloud/secret-manager";
import {GoogleAuth} from "google-auth-library";

export interface Secrets {
  getSecret(secretName: string): Promise<string>;
}

class SecretsImpl implements Secrets {
  private secrets: Map<string, string>;
  // TODO(tjohns): How (or why...) is SecretManagerServiceClient exported as a constructor but not
  // as a type
  private secretManagerServiceClient: v1.SecretManagerServiceClient;
  private auth: GoogleAuth;

  constructor(secretManagerServiceClient: v1.SecretManagerServiceClient, auth: GoogleAuth) {
    this.secrets = new Map();
    this.secretManagerServiceClient = secretManagerServiceClient;
    this.auth = auth;
  }

  async getSecret(secretName: string) {
    const secrets = this.secrets;
    const secretManagerServiceClient = this.secretManagerServiceClient;
    const auth = this.auth;

    let secret = secrets.get(secretName);

    if (!secret) {
      console.log(`No cached secret found, fetching ${secretName} from secret manager`);

      const projectId = await auth.getProjectId();

      const [accessResponse] = await secretManagerServiceClient.accessSecretVersion({
        name: `projects/${projectId}/secrets/${secretName}/versions/latest`,
      });

      secret = accessResponse.payload.data.toString()
      secrets.set(secretName, secret);
    }
    return secret;
  }
}

export function createSecretsCache(): Secrets {
  const secretManagerServiceClient = new SecretManagerServiceClient();
  const auth = new GoogleAuth();

  return new SecretsImpl(secretManagerServiceClient, auth);
}