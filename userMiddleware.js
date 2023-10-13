const { header, validationResult, ValidationChain, body, param } = require("express-validator");
const { ValidateIDToken } = require("../database/firebaseAuth");
const { BaseAuthorizationHeaderValidator, ERROR_CODES } = require("./validators");
const jwt = require("jsonwebtoken");
const { assuredworkloads } = require("googleapis/build/src/apis/assuredworkloads");
const { admin, database } = require("../firebaseconfig/firebase_config");
const UsersRef = database.collection("Users");
const { User, UserConverter } = require("../models/user");
const DevicesDb = require("../database/device.js");

/** 
Throws an error if token could not be validated using Firebase Admin SDK. 
 * @param {string} value - The bearer token containing the string `bearer`. Token must be extracted. 
 * @param {Request} req - The request object passed by express validator
*/
async function VerifyFirebaseTokenOnlyUID(value, { req }) {
  token = value.split(" ")[1];

  const { uid } = await ValidateIDToken(token);
  //If the uid is 0 here we throw and error for invalid token
  if (!uid) {
    throw new Error(ERROR_CODES.INVALID_FIREBASE_TOKEN);
  }
  req.body.userId = uid;
  return true;
}

/** 
Throws an error if the email is not verified or the token could not be validated using Firebase Admin SDK. 
 * @param {string} value - The bearer token containing the string `bearer`. Token must be extracted. 
 * @param {Request} req - The request object passed by express validator
*/
async function VerifyFirebaseToken(value, { req }) {
  token = value.split(" ")[1];
  const { uid, email_verified } = await ValidateIDToken(token);

  // If the result is 0 here we throw and error for invalid token
  if (!uid || !email_verified) {
    throw new Error(ERROR_CODES.INVALID_FIREBASE_TOKEN);
  }
  req.body.userId = uid;

  return true;
}

/**
 * Throws an error if the 2FA access token is not provided or invalid.
 */
async function VerifyAccessToken(value, {req}) {
  //check if the access token in the cookie is valid
  const {accessToken} = req.cookies;
  console.log(req.cookies)
  console.log(accessToken)
  try {
    const accessData = jwt.verify(accessToken, process.env.JWT_SECRET_KEY);
    console.log(accessData)
    if (accessData.userId !== req.body.userId || !accessData.isAccessToken) {
      throw new Error(ERROR_CODES.INVALID_ACCESS_TOKEN);
    }
  } catch (error) {
    console.log(error)
    throw new Error(ERROR_CODES.INVALID_ACCESS_TOKEN);
  }
  return true;

}

/**
 * Throws an error if the 2FA access token is not provided or invalid.
 */
async function VerifyUpdatePhoneNumber(value, {req}) {
  const userId = req.body.userId;

  //get available auth methods for the user --------------------------
  //sms is always avaliable since must have verified phone number
  const phoneVerified = (await UsersRef.doc(userId).withConverter(UserConverter).get()).get("phoneVerified");

  const availableMethods = { SMS: phoneVerified, QR: false, SSID: false, Geolocation: false };

  //find number of mobile and desktop devices
  const totalDeviceCount = (await DevicesDb.read.getAllDevices(userId)).length;
  const mobileDeviceCount = (await DevicesDb.read.getAllMobileDevices(userId)).length;
  const desktopDeviceCount = totalDeviceCount - mobileDeviceCount;

  //if at least 1 mobile, can user QR + at least 1 desktop, can also use SSID
  availableMethods.QR = mobileDeviceCount > 0;
  availableMethods.SSID = desktopDeviceCount > 0 && mobileDeviceCount > 0;
  availableMethods.Geolocation = mobileDeviceCount >0;

  //check if user has any methods of authentication
  if((availableMethods.SMS || availableMethods.QR || availableMethods.SSID || availableMethods.Geolocation) && req.body.phoneNumber) {
    return VerifyAccessToken(value, {req: req});
  }

  //if no methods of auth, let user do whatever they want
  return true;
}

/** 
An error handler function for express validator. Collects error that occured during 
the request processing stage and prepares a JSON response. Each case statement switches 
through the error message and assigns the response an error code on a case by case basis.

 * @param {Response} res - The response body of the request that must be modified to set reponse code.
 * @param {Request} req - The request object passed by express validator
 * @param {function} next- The next function called (the main request handler) if there are no errors. 
*/
const AuthValidate = async (req, res, next) => {
  const errors = validationResult(req);

  if (errors.isEmpty()) {
    return next();
  }

  const message = errors.array()[0].msg; //Get the first error message

  const errorCode = message.split(":")[0]
  const param = message.split(":")[1]

  switch (errorCode) {
    case ERROR_CODES.MISSING_HEADER:
      res.status(403).json({
        error: errorCode,
      });
      break;
    case ERROR_CODES.MISSING_BEARER:
      res.status(403).json({
        error: errorCode,
      });
      break;
    case ERROR_CODES.INVALID_FIREBASE_TOKEN:
      res.status(400).json({
        error: errorCode,
      });
      break;
    case ERROR_CODES.DEVICE_EXISTS:
      res.staus(401).json({
        error: errorCode,
      });
      break;
    case ERROR_CODES.PHONE_NUMBER_NOT_VERIFIED:
      return res.status(409).json({
        error: errorCode,
      });
      break;
    case ERROR_CODES.MISSING_PARAMATER.split(":")[0]:
      return res.status(412).json({
        success: false,
        error: errorCode + param,
      });
      break;
    case ERROR_CODES.INVALID_ACCESS_TOKEN:
        return res.status(417).json({
          success: false,
          error: errorCode,
        })
    default:
      return res.status(400).json({
        error: errorCode,
      });
      break;
  }
};

/**
 * Middleware to check if the user has a valid access token. Adds that as a boolean value to body.
 */
const CheckAccessTokenMiddleware = (req, res, next) => {
  
  //create hasAccess property for body
  req.body.hasAccess = true;

  //check if the access token in the cookie is valid
  const {accessToken} = req.cookies;
  console.log(req.cookies)
  try {
    const accessData = jwt.verify(accessToken, process.env.JWT_SECRET_KEY);
    if (accessData.userId !== req.body.userId || !accessData.isAccessToken) {
      req.body.hasAccess = false;
    }
  } catch (error) {
    req.body.hasAccess = false;
  }

  next();
}

/*
The express validation chain for /basic-info in User router.
The user ID extracted through the Firebase token using VerifyFirebaseToken
*/
const UserBasicLoginValidator = () => {
  return [BaseAuthorizationHeaderValidator().custom(VerifyFirebaseTokenOnlyUID)];
};

/*
The express validation chain for /checkPhoneNumberChange.
 */
const CheckPhoneNumberChangeValidator = () => {
  return [BaseAuthorizationHeaderValidator().custom(VerifyFirebaseToken),
    BaseAuthorizationHeaderValidator().custom(VerifyAccessToken)]
}

/*
The express validation chain for /storeAccessToken in User router.
The user ID extracted through the Firebase token using VerifyFirebaseToken
*/
const StoreAccessTokenValidator = () => {
  return [BaseAuthorizationHeaderValidator().custom(VerifyFirebaseToken),
    body("successJWT").isLength({ min: 1 }).trim().withMessage(`${ERROR_CODES.MISSING_PARAMATER} successJWT`).bail()
  ];
};

// Deprecated currently.
const UserLoginValidator = () => {
  return [BaseAuthorizationHeaderValidator().custom(VerifyFirebaseToken)];
};

/*
The express validation chain for /registerStepOne in User router.
isLength({min:1}) ensures that the string is non-empty in the body or paramater. 
The user ID extracted through the Firebase token using VerifyFirebaseToken
.bail() ensures that the request does not proceed to another validator further if the current validation fails.
*/
const UserRegistrationValidator = () => {
  return [
    BaseAuthorizationHeaderValidator().custom(VerifyFirebaseTokenOnlyUID),
    body("username").isLength({ min: 1 }).trim().withMessage(`${ERROR_CODES.MISSING_PARAMATER} username`).bail(),
    body("name").isLength({ min: 1 }).trim().withMessage(`${ERROR_CODES.MISSING_PARAMATER} name`).bail(),
    // body("phoneNumber").isLength({ min: 1 }).trim().withMessage(`${ERROR_CODES.MISSING_PARAMATER} phoneNumber`).bail(),
  ];
};

// Deprecated currently.
const UserRegistrationStep2Validator = () => {
  return [BaseAuthorizationHeaderValidator().custom(VerifyFirebaseToken)];
};

/*
The express validation chain for /updatePhone in User router.
The user ID extracted through the Firebase token using VerifyFirebaseToken
isLength({min:1}) ensures that the string is non-empty in the body or paramater. 
.bail() ensures that the request does not proceed to another validator further if the current validation fails.
*/
const UpdatePhoneNumberValidator = () => {
  return [
    BaseAuthorizationHeaderValidator().custom(VerifyFirebaseToken),
    BaseAuthorizationHeaderValidator().custom(VerifyUpdatePhoneNumber),
    param("phoneNumber").isLength({ min: 1 }).trim().isMobilePhone().withMessage(`${ERROR_CODES.MISSING_PARAMATER} phoneNumber`).bail(),
  ];
};

/*
The express validation chain for /setFCMToken in User router.
The user ID extracted through the Firebase token using VerifyFirebaseToken
isLength({min:1}) ensures that the string is non-empty in the body or paramater. 
.bail() ensures that the request does not proceed to another validator further if the current validation fails.
*/
const SetFCMTokenValidator = () => {
  return [
    BaseAuthorizationHeaderValidator().custom(VerifyFirebaseToken),
    BaseAuthorizationHeaderValidator().custom(VerifyAccessToken),
    body("FCMToken").isLength({ min: 1 }).trim().withMessage(`${ERROR_CODES.MISSING_PARAMATER} FCMToken`).bail(),
  ];
};

/*
The express validation chain for /updateField in User router.
The user ID extracted through the Firebase token using VerifyFirebaseToken
isLength({min:1}) ensures that the string is non-empty in the body or paramater. 
.bail() ensures that the request does not proceed to another validator further if the current validation fails.
*/
const UpdateFieldValidator = () => {
  return [
    BaseAuthorizationHeaderValidator().custom(VerifyFirebaseToken),
    BaseAuthorizationHeaderValidator().custom(VerifyAccessToken),
    body("field").isLength({ min: 1 }).trim().withMessage(`${ERROR_CODES.MISSING_PARAMATER} field`).bail(),
    body("info").isLength({ min: 1 }).trim().withMessage(`${ERROR_CODES.MISSING_PARAMATER} info`).bail(),
  ];
};

/*
The express validation chain for /delete in User router.
The user ID extracted through the Firebase token using VerifyFirebaseToken
*/
const DeleteValidator = () => {
  return [
    BaseAuthorizationHeaderValidator().custom(VerifyFirebaseToken),
    BaseAuthorizationHeaderValidator().custom(VerifyAccessToken),
  ];
};

/*
The express validation chain for /getAvailableAuthMethods in User router.
isLength({min:1}) ensures that the string is non-empty in the body or paramater. 
.bail() ensures that the request does not proceed to another validator further if the current validation fails.
*/
const GetAvailableAuthMethodsValidator = () => {
  return [
    body("encData").isLength({ min: 1 }).trim().withMessage(`${ERROR_CODES.MISSING_PARAMATER} encData`).bail(),
    body("hash").isLength({ min: 1 }).trim().withMessage(`${ERROR_CODES.MISSING_PARAMATER} hash`).bail(),
    body("organizationId").isLength({ min: 1 }).trim().withMessage(`${ERROR_CODES.MISSING_PARAMATER} organizationId`).bail(),
    body("time").isLength({ min: 1 }).trim().withMessage(`${ERROR_CODES.MISSING_PARAMATER} time`).bail()
  ];
};

/*
The express validation chain for /delete in User router.
The user ID extracted through the Firebase token using VerifyFirebaseToken
*/
const RegisteredOrganizationsalidator = () => {
  return [
    BaseAuthorizationHeaderValidator().custom(VerifyFirebaseToken)
  ];
};

module.exports = {
  UserLoginValidator,
  UserBasicLoginValidator,
  UserRegistrationValidator,
  UserRegistrationStep2Validator,
  VerifyFirebaseToken,
  VerifyAccessToken,
  AuthValidate,
  SetFCMTokenValidator,
  StoreAccessTokenValidator,
  UpdatePhoneNumberValidator,
  UpdateFieldValidator,
  DeleteValidator,
  GetAvailableAuthMethodsValidator,
  CheckAccessTokenMiddleware,
  CheckPhoneNumberChangeValidator,
  RegisteredOrganizationsalidator
};
