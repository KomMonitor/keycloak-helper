const axios = require("axios");
const fs = require("fs");
const logger = require('./utils/logger');

var kommonitorAdminRole = undefined;
var kommonitorConfigRolesPostfixes = undefined;

var keycloakTargetURL = undefined;
var keycloakUser = undefined;
var keycloakUserPassword = undefined;
var keycloakClientID = undefined;
var keycloakClientSecret = undefined;
var keycloakRealm = undefined;

const initKeycloakHelper = function (authServerUrl, realm, clientId, clientSecret, kommonitorAdminUsername, kommonitorAdminUserPassword, kommonitorAdminRolename, kommonitorConfigAllowedRolesPostfixes) {
  keycloakTargetURL = authServerUrl;
  keycloakRealm = realm;
  keycloakClientID = clientId;
  keycloakClientSecret = clientSecret;
  keycloakUser = kommonitorAdminUsername;
  keycloakUserPassword = kommonitorAdminUserPassword;
  kommonitorAdminRole = kommonitorAdminRolename;
  kommonitorConfigRolesPostfixes = kommonitorConfigAllowedRolesPostfixes;
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

  if(keycloakClientSecret){
    parameters["client_secret"] = keycloakClientSecret;
  }

  var keycloakBearerTokenURL = keycloakTargetURL + "realms/" + keycloakRealm + "/protocol/openid-connect/token";

  const config = {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    }
  }

  return await axios.post(keycloakBearerTokenURL, new URLSearchParams(parameters).toString(), config)
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
      logger.error("Error while requesting auth bearer token from keycloak. Error is: \n" + error);
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
    "client_secret": keycloakClientSecret,
  };

  var keycloakIntrospectTokenURL = keycloakTargetURL + "realms/" + keycloakRealm + "/protocol/openid-connect/token/introspect";

  const config = {
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    }
  }

  return await axios.post(keycloakIntrospectTokenURL, new URLSearchParams(parameters).toString(), config)
    .then((response) => {
      return response.data;
    })
    .catch((error) => {
      // called asynchronously if an error occurs
      // or server returns response with an error status.
      //$scope.error = response.statusText;
      logger.error("Error while requesting token introspection from keycloak. Error is: \n" + error);
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

  let roles = await getRolesFromKeycloakToken(token);
  return roles.includes(kommonitorAdminRole);
};

const checkKeycloakProtection = async function (req, res, next, method) {
  const methods = Array.isArray(method) ? method : [method];

  if (methods.includes(req.method)) {
    logger.info("Itercepting " + req.method + " request. Check for Keycloak-based Admin permission.");

    let authHeaderValue = req.header("Authorization");

    if (!authHeaderValue) {
      logger.warn('No Authorization header present.');
      res.status(401).send('Access to protected endpoint with ' + req.method + ' method is only allowed for KomMonitor Admin users.');
    }
    else if (authHeaderValue && !authHeaderValue.includes("Bearer")) {
      logger.warn('Authorization header not using Bearer token mechanism.');
      res.status(401).send('Access to protected endpoint with ' + req.method + ' method is only allowed for KomMonitor Admin users using Bearer token.');
    }
    else {
      let token = authHeaderValue.split(" ")[1];
      logger.debug(token);
      let isAdmin = await isAdminUser(token);
      if (isAdmin) {
        logger.info("Admin authenticated. Continue request");
        next();
      }
      else {
        logger.warn("Non-Admin authenticated. Hence block request.");
        res.status(403).send('Access to protected endpoint with ' + req.method + ' method is only allowed for KomMonitor Admin users.');
      }
    }
  }
  else {
    next();
  }
};

const checkForUserRolePostfix = async function (token, postfix) {
  let roles = await getRolesFromKeycloakToken(token);
  return roles.some(role => role.endsWith(postfix));
};

async function checkForAllowedUserRole(token, postfixes) {
  for (const postfix of postfixes) {
    if (await checkForUserRolePostfix(token, postfix)) {
      return true;
    }
  }
  return false;
}

const checkKeycloakProtectionClientConfig = async function (req, res, next, method) {

  if (req.method == method) {
    logger.info("Itercepting " + req.method + " request. Check for Keycloak-based Resource Creator permission.");

    let authHeaderValue = req.header("Authorization");

    if (!authHeaderValue) {
      logger.warn('No Authorization header present.');
      res.status(401).send('Access to protected endpoint with ' + req.method + ' method is only allowed for KomMonitor Resource Creator users.');
    }
    else if (authHeaderValue && !authHeaderValue.includes("Bearer")) {
      logger.warn('Authorization header not using Bearer token mechanism.');
      res.status(401).send('Access to protected endpoint with ' + req.method + ' method is only allowed for KomMonitor Resource Creator users using Bearer token.');
    }
    else {
      let token = authHeaderValue.split(" ")[1];
      logger.debug(token);
      let hasAllowedUserRole = await checkForAllowedUserRole(token, kommonitorConfigRolesPostfixes);
      let isAdmin = await isAdminUser(token);
      if (hasAllowedUserRole || isAdmin) {
        logger.info("Resource Creator authenticated. Continue request");
        next();
      }
      else {
        logger.warn("Non- Resource Creator authenticated. Hence block request.");
        res.status(403).send('Access to protected endpoint with POST method is only allowed for KomMonitor Resource Creator users.');
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
exports.checkKeycloakProtectionClientConfig = checkKeycloakProtectionClientConfig;