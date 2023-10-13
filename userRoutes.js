const express = require("express");
const {
  UserBasicLoginValidator,
  UserRegistrationValidator,
  AuthValidate,
  UpdatePhoneNumberValidator,
  SetFCMTokenValidator,
  StoreAccessTokenValidator,
  UpdateFieldValidator,
  DeleteValidator,
  GetAvailableAuthMethodsValidator,
  CheckAccessTokenMiddleware,
  CheckPhoneNumberChangeValidator,
  RegisteredOrganizationsalidator
} = require("../middleware/userMiddleware");
const UsersDb = require("../database/user.js");
const DeviceDb = require("../database/device.js");
const OrganizationDb = require("../database/organization.js");
const DevicesDb = require("../database/device");
const { GetAuthJWTValidator } = require("../middleware/organizationMiddleware");
const jwt = require("jsonwebtoken");
const createError = require("http-errors");
const { EndUserInstance } = require("twilio/lib/rest/trusthub/v1/endUser");
const UserRouter = express.Router();

// ----------------------------------------------GET----------------------------------------------------- //

/**
 * Get basic info for a user.
 */
UserRouter.get("/basicInfo", UserBasicLoginValidator(), AuthValidate, CheckAccessTokenMiddleware, async (req, res) => {
  let userId = req.body.userId;
  UsersDb.read
    .GetUserFromUID(userId)
    .then(async (basicInfo) => {
      //blur phone number
      const phoneNumber = basicInfo.phoneNumber;
      basicInfo.phoneNumber = phoneNumber.substring(0, 2) + "(***) ***-" + phoneNumber.substring(8, 12);
      //get available auth methods for the user --------------------------
      //sms is always avaliable since must have verified phone number
      const availableMethods = { SMS: basicInfo.phoneVerified };

      //find number of mobile and desktop devices
      const totalDeviceCount = (await DevicesDb.read.getAllDevices(userId)).length;
      const mobileDeviceCount = (await DevicesDb.read.getAllMobileDevices(userId)).length;
      const desktopDeviceCount = totalDeviceCount - mobileDeviceCount;

      //if at least 1 mobile, can user QR + at least 1 desktop, can also use SSID
      availableMethods.QR = mobileDeviceCount > 0;
      availableMethods.SSID = desktopDeviceCount > 0 && mobileDeviceCount > 0;
      availableMethods.Geolocation = desktopDeviceCount > 0 && mobileDeviceCount > 0;

      if (availableMethods.SSID) {
        availableMethods.Smart = true;
      }

      res.status(200).json({
        userId: req.body.userId,
        ...basicInfo,
        availableAuthMethods: availableMethods,
        hasAccess: req.body.hasAccess
      });
    })
    .catch((error) => {
      console.error(`${error.message}`);
      res.status(error.status).json({ error: error.message });
    });
});

UserRouter.get("/registeredOrganizations", RegisteredOrganizationsalidator(), AuthValidate, async function (req, res) {
  const userId = req.body.userId;
  try {
    const registeredOrganizations = await UsersDb.read.GetOrganizationsFromUID(userId);

    if (registeredOrganizations.length == 0) {
      return res.status(401).json({ success: false, message: "No registered organizations"})
    }

    let organizationsInfo = []

    for (organizationId of registeredOrganizations) {
      let organizationInfo = await OrganizationDb.read.getOrganizationInfo(organizationId)

      organizationsInfo.push(organizationInfo)
    }

    return res.status(200).json({ success: true, organizationsInfo: organizationsInfo });

  } catch (error) {
    console.log(error);
    if (!error.status) {
      error.status = 500;
    }
    return res.status(error.status).json({ success: false, error: error.message });
  }
})

/**
 * Verify if a username is unique (does not exist in the firestore already).
 */
UserRouter.get("/verifyUsername/:username", async function (req, res) {
  if (!req.params.username) {
    return res.status(500).json({ error: "Username not defined" });
  }

  UsersDb.read
    .getUsernameUnique(req.params.username.toLowerCase())
    .then((unique) => {
      return res.status(200).json({ unique });
    })
    .catch((error) => {
      return res.status(500).json({ error: error.message });
    });
});

/**
 * Check if the provided phone number is the same as the phone number stored in the database for a user.
 */
UserRouter.get("/checkPhoneNumberChange/:phoneNumber", CheckPhoneNumberChangeValidator(), AuthValidate, async function (req, res) {
  if(!req.params.phoneNumber) {
    return res.status(500).json({error: "Phone number not provided."});
  }

  try {
    const basicInfo = await UsersDb.read.GetUserFromUID(req.body.userId);
    const isSame = req.params.phoneNumber === basicInfo.phoneNumber;
    return res.status(200).json({same: isSame});
  } catch (error) {
    console.error(`${error.message}`);
    res.status(error.status).json({ error: error.message });
  }  
})

// ----------------------------------------------POST (Create)----------------------------------------------------- //

/**
 * Application-wide testing route to check if POST requests can be successfully made to the backend.
 */
UserRouter.post("/", async (req, res) => {
  return res.status(200).json({ response: req.body });
});

/**
 * Register/create a user with basic info in the firestore.
 */
UserRouter.post("/registerStepOne", UserRegistrationValidator(), AuthValidate, async function (req, res) {
  const user = req.body;
  UsersDb.create
    .createUser(user)
    .then((result) => {
      res.status(200).json({ success: true });
    })
    .catch((error) => {
      console.log(error);
      return res.status(error.status).json({ error: error.message });
    });
});

/**
 * Stores an access token with userId and isAccessToken = true
 * In body, must receive successJWT and must receive a firebase auth token in the header.
 */
UserRouter.post("/storeAccessToken", StoreAccessTokenValidator(), AuthValidate, async (req, res, next) => {
  try {
    //validate the given successJWT and check if UID matches UID in JWT
    let userId;
    try {
      userId = jwt.verify(req.body.successJWT, process.env.JWT_SECRET_KEY).userId;
    } catch (error) {
      console.log(error);
      throw createError(406, "Success JWT Invalid.");
    }

    if (userId !== req.body.userId) {
      throw createError(401, "Users do not match.");
    }

    //create JWT with uid
    const accessToken = jwt.sign({ userId: userId, isAccessToken: true }, process.env.JWT_SECRET_KEY, {
      expiresIn: 6000,
    });
    console.log(accessToken)
    // res.header('Access-Control-Allow-Credentials', true);
    // // res.header('Access-Control-Expose-Headers', 'set-cookie'); // Add this line

    // res.setHeader('Access-Control-Expose-Headers', '*')
    //store in a http only cookie
    res.cookie('accessToken', accessToken, 
    {
      httpOnly: true, // This makes the cookie HTTP-only
      secure: true, // This ensures the cookie is only sent over HTTPS,
      sameSite: "None",
      maxAge: "100000000"
    }
    );
    


    res.status(200).json({ message: "Successfully stored access token."});
  } catch (error) {
    console.log(error);
    if (!error.status) {
      error.status = 500;
    }
    return res.status(error.status).json({ error: error.message });
  }
});

// ----------------------------------------------UPDATE----------------------------------------------------- //

/**
 * Updatea a particular field for a user in the firestore.
 */
UserRouter.post("/updateField", UpdateFieldValidator(), AuthValidate, async (req, res, next) => {
  const userId = req.body.userId;
  const field = req.body.field;
  const info = req.body.info;

  UsersDb.update
    .updateField(userId, field, info)
    .then((result) => {
      res.status(200).json({ success: true });
    })
    .catch((error) => {
      console.log(error.message);
      return res.status(error.status).json({ error: error.message });
    });
});

/**
 * Update the phone number of a user in the firestore.
 */
UserRouter.post("/updatePhone/:phoneNumber", UpdatePhoneNumberValidator(), AuthValidate, async (req, res) => {
  let queryTime = await UsersDb.update.updatePhoneNumber(req.body.userId, req.params.phoneNumber).catch((error) => {
    console.log(error);
    return res.status(error.status).json({ error: error.message });
  });
  return res.status(200).json({ success: true });
});

// /**
//  * Currently unused since FCM tokens for the frontend for a user are not being stored.
//  */
// UserRouter.post("/setFCMToken", SetFCMTokenValidator(), AuthValidate, async (req, res, next) => {
//   const userId = req.body.userId;
//   const FCMToken = req.body.FCMToken;
//   UsersDb.update
//     .setFCMToken(userId, FCMToken)
//     .then(() => {
//       res.status(200).json({ success: true });
//     })
//     .catch((error) => {
//       console.error(`${error.message}`);
//       res.status(error.status).json({ error });
//     });
// });

// ----------------------------------------------DELETE----------------------------------------------------- //

/**
 * Delete a user by userId from the firestore.
 */
UserRouter.post("/delete", DeleteValidator(), AuthValidate, async (req, res) => {
  const userId = req.body.userId;
  UsersDb.delete
    .DeleteUserFromUID(userId)
    .then((writeTime) => {
      res.status(200).json({ success: true });
    })
    .catch((error) => {
      res.status(500).json({ error: error });
    });
});

/**
 * Get which authentication method (SSID, QR, SMS) a user can use depending on their registered devices
 */
UserRouter.post("/getAvailableAuthMethods", GetAvailableAuthMethodsValidator(), AuthValidate, async (req, res) => {
  try {
    //sms is always avaliable since must have verified phone number
    const availableMethods = { SMS: true, QR: false, SSID: false };

    //decrypt encData to get userId
    await OrganizationDb.validate.validateOrganizationRequest(req);

    const userId = req.body.userId;
    //find number of mobile and desktop devices
    const totalDeviceCount = (await DeviceDb.read.getAllDevices(userId)).length;
    const mobileDeviceCount = (await DeviceDb.read.getAllMobileDevices(userId)).length;
    const desktopDeviceCount = totalDeviceCount - mobileDeviceCount;

    //if atleast one desktop and mobile device, can use ssid and qr
    if (desktopDeviceCount > 0 && mobileDeviceCount > 0) {
      availableMethods.QR = true;
      availableMethods.SSID = true;
      //if atleast one mobile, can use qr
    } else if (mobileDeviceCount > 0) {
      availableMethods.QR = true;
    }

    return res.status(200).json(availableMethods);
  } catch (error) {
    console.error(`${error.message}`);
    if (!error.status) {
      error.status = 500;
    }
    res.status(error.status).json({ error: error.message });
  }
});

module.exports = UserRouter;
