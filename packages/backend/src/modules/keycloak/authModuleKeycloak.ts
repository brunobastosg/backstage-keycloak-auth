import { createBackendModule } from '@backstage/backend-plugin-api';
import {
  authProvidersExtensionPoint,
  createProxyAuthProviderFactory,
} from '@backstage/plugin-auth-node';
import { oauth2ProxyAuthenticator } from '@backstage/plugin-auth-backend-module-oauth2-proxy-provider';
import {
  stringifyEntityRef,
  DEFAULT_NAMESPACE,
} from '@backstage/catalog-model';

export const authModuleKeycloak = createBackendModule({
  pluginId: 'auth',
  moduleId: 'keycloak-auth',
  register(reg) {
    reg.registerInit({
      deps: { providers: authProvidersExtensionPoint },
      async init({ providers }) {
        providers.registerProvider({
          providerId: 'oauth2Proxy',
          factory: createProxyAuthProviderFactory({
            authenticator: oauth2ProxyAuthenticator,
            async signInResolver({ result }, ctx) {
              const email = result.getHeader('x-forwarded-email');
              if (!email) {
                throw new Error('Request did not contain a user');
              }

              const name = email.substring(0, email.indexOf('@'));

              try {
                // Attempts to sign in existing user
                const signedInUser = await ctx.signInWithCatalogUser({
                  entityRef: { name },
                });

                return Promise.resolve(signedInUser);
              } catch (e) {
                // Create stub user
                const userEntityRef = stringifyEntityRef({
                  kind: 'User',
                  name: name,
                  namespace: DEFAULT_NAMESPACE,
                });
                return ctx.issueToken({
                  claims: {
                    sub: userEntityRef,
                    ent: [userEntityRef],
                  },
                });
              }
            },
          }),
        });
      },
    });
  },
});

export { authModuleKeycloak as default } from './authModuleKeycloak';
