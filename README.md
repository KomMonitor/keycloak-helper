# keycloak-helper
a small helper service for NodeJS apps to authenticate to Keycloak

# usage hints
Use it in two steps.

1. install in node app directly from github ``` npm install --save https://github.com/KomMonitor/keycloak-helper ```
2. require helper service 
    ``` let keycloakHelperService = require('keycloak-helper'); ``` 
3. initialize helper service parameters required to perform keycloak authentication services 
    ``` keycloakHelperService.initKeycloakHelper(authServerUrl, realm, clientId, clientSecret, kommonitorAdminUsername, kommonitorAdminUserPassword, kommonitorAdminRolename)```
2. perform authentication action, by either calling
    - ``` requestAccessToken() ``` to request an access token as a KomMonitor Admin user
    - ``` getRolesFromKeycloakToken(token) ``` to request role names of a valid submitted keycloak token
    - ``` isAdminUser(token) ``` to request whether the submitted keycloak token resolves to a user with KomMonitor admin rights
    - ``` checkKeycloakProtection(req, res, next, method) ``` as express middleware in order to intercept any incoming requests and perform keycloak protection checks for KomMonitor
    i.e. as should be integrated as the first middleware when instantiating express like so:
    ``` 
        let app = express();
    
        app.use(async function(req, res, next) {
            // intercept requests to perform any keycloak protection checks.
            await keycloakHelperService.checkKeycloakProtection(req, res, next, "POST");
        }); 
    ``` 
    

