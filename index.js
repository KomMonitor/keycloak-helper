const qs = require('querystring');
const axios = require("axios");
const fs = require("fs");

var kommonitorAdminRole = undefined;

var keycloakTargetURL = undefined;
var keycloakUser = undefined;
var keycloakUserPassword = undefined;
var keycloakClientID = undefined;
var keycloakClientSecret = undefined;
var keycloakRealm = undefined;

const initKeycloakHelper = function (authServerUrl, realm, clientId, clientSecret, kommonitorAdminUsername, kommonitorAdminUserPassword, kommonitorAdminRolename) {
  keycloakTargetURL = authServerUrl;
  keycloakRealm = realm;
  keycloakClientID = clientId;
  keycloakClientSecret = clientSecret;
  keycloakUser = kommonitorAdminUsername;
  keycloakUserPassword = kommonitorAdminUserPassword;
  kommonitorAdminRole = kommonitorAdminRolename;
};

const requestKeycloakToken = async function () {
  var parameters = {
    "username": keycloakUser,
    "password": keycloakUserPassword,
    "client_id": keycloakClientID,
    "grant_type": "password",
    // "grant_type" : "urn:ietf:params:oauth:grant-type:token-exchange",
    // "client_secret": keycloakClientSecret
  };

  var keycloakBearerTokenURL = keycloakTargetURL + "realms/" + keycloakRealm + "/protocol/openid-connect/token";

  const config = {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    }
  }

  return await axios.post(keycloakBearerTokenURL, qs.stringify(parameters), config)
    .then((response) => {
      /*
        {
            "access_token": "tokenString",
            "expires_in": 60,
            "refresh_expires_in": 1800,
            "refresh_token": "tokenString",
            "token_type": "bearer",
            "not-before-policy": 0,
            "session_state": "5d9d8418-be24-4641-a47c-3309bb243d8d",
            "scope": "email profile"
        }
      */
      return response.data["access_token"];
    })
    .catch((error) => {
      // called asynchronously if an error occurs
      // or server returns response with an error status.
      //$scope.error = response.statusText;
      console.error("Error while requesting auth bearer token from keycloak. Error is: \n" + error);
      throw error;
    })
};

const requestAccessToken = async function () {

  var config = {
    headers: {}
  };

  if (JSON.parse(process.env.KEYCLOAK_ENABLED)) {
    // get bearer token and make auth header
    var bearerToken = await requestKeycloakToken();

    config.headers = {
      'Authorization': 'Bearer ' + bearerToken
    }
  }

  return config;
};

const introspectKeycloakToken = async function (token) {
  var parameters = {
    "token": token,
    "client_id": keycloakClientID,
    // "secret": keycloakClientSecret,
    "client_secret": keycloakClientSecret,
  };

  var keycloakIntrospectTokenURL = keycloakTargetURL + "realms/" + keycloakRealm + "/protocol/openid-connect/token/introspect";

  const config = {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    }
  }

  return await axios.post(keycloakIntrospectTokenURL, qs.stringify(parameters), config)
    .then((response) => {
      return response.data;
    })
    .catch((error) => {
      // called asynchronously if an error occurs
      // or server returns response with an error status.
      //$scope.error = response.statusText;
      console.error("Error while requesting token introspection from keycloak. Error is: \n" + error);
      throw error;
    })
};

const getRolesFromKeycloakToken = async function (token) {

  let tokenInformation = await introspectKeycloakToken(token);
  if (tokenInformation && tokenInformation.realm_access && tokenInformation.realm_access.roles){
    return tokenInformation.realm_access.roles;
  } 
  else{
    return [];
  }
};

const isAdminUser = async function (token) {

  let roles = await getRolesFromKeycloakToken();
  return roles.includes(kommonitorAdminRole);
};

const checkKeycloakProtection = async function (req, res, next, method) {

  if (req.method == method) {
    console.log("Itercepting " + req.method + " request. Check for Keycloak-based Admin permission.");

    let authHeaderValue = req.header("Authorization");

    if (!authHeaderValue) {
      console.log('No Authorization header present.');
      res.status(401).send('Access to protected endpoint with POST method is only allowed for KomMonitor Admin users.');
    }
    else if (authHeaderValue && !authHeaderValue.includes("Bearer")) {
      console.log('Authorization header not using Bearer token mechanism.');
      res.status(401).send('Access to protected endpoint with POST method is only allowed for KomMonitor Admin users using Bearer token.');
    }
    else {
      let token = authHeaderValue.split("Bearer ")[0];
      console.log(token);
      let isAdmin = await isAdminUser(token);
      if (isAdmin) {
        console.log("Admin authenticated. Continue request");
        next();
      }
      else {
        console.log("Non-Admin authenticated. Hence block request.");
        res.status(403).send('Access to protected endpoint with POST method is only allowed for KomMonitor Admin users.');
      }
    }
  }
  else {
    next();
  }
};

exports.initKeycloakHelper = initKeycloakHelper;
exports.requestKeycloakToken = requestKeycloakToken;
exports.requestAccessToken = requestAccessToken;
exports.introspectToken = introspectKeycloakToken;
exports.getRolesFromKeycloakToken = getRolesFromKeycloakToken;
exports.isAdminUser = isAdminUser;
exports.checkKeycloakProtection = checkKeycloakProtection;