const { User, UserConverter } = require("../models/user");
const { collection, addDoc } = require("firebase/firestore");
const { admin, database } = require("../firebaseconfig/firebase_config");
const createError = require("http-errors");
const { query } = require("express");
const crypto = require("crypto");
const cryptLib = require("@skavinvarnan/cryptlib"); // https://github.com/skavinvarnan/Cross-Platform-AES


// Users collection in firestore database
const UsersRef = database.collection("Users");
const UsersHashRef = database.collection("UsersHash")

// ----------------------------------------------Create----------------------------------------------------- //

/** 
 * @returns {Promise<admin.firestore.WriteResult>}
 Inserts a new user with the userId as the document ID into the ftirestore database.
 Throws a 409 error if the username already exists and a 500 error if there was an internal error
 with the network request.
 * @param {Object} user - The user object containing userId/username, name and PhoneNumber 
 that must be set in the doc. 
*/
async function createUser(user) {
  let usernameCheck = await getUsernameUnique(user.username).catch(() => {
    throw createError(500, "Unexpected network request error");
  });
  if (!usernameCheck) {
    throw createError(409, "Username Already Exists");
  }

  return await UsersRef.doc(user.userId)
    .withConverter(UserConverter)
    .set(
      new User(
        user.userId,
        user.username,
        admin.firestore.FieldValue.serverTimestamp(), // user.regDate
        // false, // user.emailVerified
        user.name,
        user.phoneNumber,
        false, // user.phoneVerified,
        crypto.randomBytes(32).toString("base64") // user.secret
      )
    );
}

/** 
 * @returns {Promise<admin.firestore.WriteResult>}
 Inserts a user with the userId hashed with a random secret as the document ID 
 into the firestore database mapping the hash to the orginal userId
 * @param {Object} userId - The userId
 * @param {Object} secret - the secret to hash with
*/
async function createUserHash(userId, secret) {

  const hashedUserId = cryptLib.getHashSha256(userId + "||" + secret, 64);
  const currentTime = new Date();

  return await UsersHashRef.doc(hashedUserId).set({ userId: userId, timestamp: currentTime.getTime(), secret: secret})

}

module.exports.create = {
  createUser,
  createUserHash
};

// ----------------------------------------------Read----------------------------------------------------- //

/** 
 * @returns {Object}
 Get the user document from Firestore through the user_id used earlier in CreateNewUser. 
 Throws a 401 error if the user cannot be found in the database using the user_id.
 * @param {String} user_id - String object of the user_id created using Firebase Authentication.
*/
async function GetUserFromUID(user_id) {
  var user = await UsersRef.doc(user_id).withConverter(UserConverter).get();
  if (!user.exists) {
    throw createError(401, "User could not be retrieved from User ID");
  }

  const info = {
    username: user.get("username"),
    name: user.get("name"),
    phoneNumber: user.get("phoneNumber"),
    phoneVerified: user.get("phoneVerified")
  };
  return info;
}

/** 
 * @returns {Object}
  Returns the user secret token from the Firestore database. Throws a 401 error if 
 the user cannot be found in the database using the user_id.
 * @param {String} user_id - String object of the user_id created using Firebase Authentication.
*/
async function GetUserSecretFromUID(user_id) {
  var user = await UsersRef.doc(user_id).withConverter(UserConverter).get();
  if (!user.exists) {
    throw createError(401, "User secret could not be retrieved from User ID");
  }

  return user.get("secret");
}

/** 
 * @returns {Boolean}
  Returns a Boolean to indicate if the username is unique. False means that username is not unique 
  while true means that the username is unique and can be used. 
 * @param {String} username - String object of the username that needs to be checked for uniqueness. 
*/
async function getUsernameUnique(username) {
  try {
    let result = await UsersRef.where("username", "==", username).get();
    return result.size > 0 ? false : true;
  } catch (error) {
    console.error(error);
    return false;
  }
}

/** 
 * @returns {Object}
 Get all registered Organizations under a user using the user_id
 Throws a 401 error if the user cannot be found in the database using the user_id.
 * @param {String} user_id - String object of the user_id created using Firebase Authentication.
*/
async function GetOrganizationsFromUID(user_id) {

  var user = await UsersRef.doc(user_id).withConverter(UserConverter).get();
  if (!user.exists) {
    throw createError(401, "User could not be retrieved from User ID");
  }

  let organizationsId = []

  await UsersRef.doc(user_id).collection("organizations").get().then((organizationIdDoc) => {
    organizationIdDoc.forEach((doc) => {
      organizationsId.push(doc.id)
    });
  }); 

  return organizationsId;
};

/** 
 * @returns {Object}
 Get the userId from the hash
 * @param {String} hashedUserId
*/
async function getUserIdFromHash(hashedUserId) {

  const user = await UsersHashRef.doc(hashedUserId).get();
  if (!user.exists) {
    throw createError(401, "User could not be retrieved.");
  }

  const currentTime = new Date();
  const hashedTime = user.get("timestamp");
  if (currentTime.getTime() - hashedTime > 60000) {
    await UsersHashRef.doc(hashedUserId).delete()
    throw createError(410, "Session timeout.");
  }

  await UsersHashRef.doc(hashedUserId).delete()

  return user.get("userId")
  
};

module.exports.read = {
  getUsernameUnique,
  GetUserFromUID,
  GetUserSecretFromUID,
  GetOrganizationsFromUID,
  getUserIdFromHash
};

// ----------------------------------------------Update----------------------------------------------------- //

/** 
 * @returns {FirebaseFirestore.Timestamp.toDate}
  Returns a timestamp indicating the date of change if the change is successful. 
  Otherwise, it throws an error in the event of a runtime error. 
 * @param {String} UserId - String object of the userId created using Firebase Authentication.
 * @param {String} phoneNumber - Phone number object parsed through the request body. It is the phone number to which 
 * we update the user number. 
*/
async function updatePhoneNumber(userId, phoneNumber) {
  let user = await UsersRef.doc(userId)
    .update({
      phoneNumber: phoneNumber,
      phoneVerified: false,
    })
    .catch((error) => {
      console.error(error);
      throw error;
    });
  return user.writeTime.toDate();
}

// /**
//  * @returns {FirebaseFirestore.Timestamp.toDate}
//   Returns a timestamp indicating the date of change if the change is successful.
//   Otherwise, it throws an error in the event of a runtime error.
//  * @param {String} UserId - String object of the user_id created using Firebase Authentication.
//  * @param {String} FCMToken - The new FCM token to set for the user's frontend
// */
// async function setFCMToken(userId, FCMToken) {
//   let user = await UsersRef.doc(userId)
//     .update({
//       FCMToken: FCMToken,
//     })
//     .catch((error) => {
//       console.error(error);
//       throw error;
//     });
//   return user.writeTime.toDate();
// }

/** 
 * @returns {FirebaseFirestore.Timestamp.toDate}
  Returns a timestamp indicating the date of change if the change is successful. 
  Otherwise, it throws an error in the event of a runtime error. 
 * @param {String} UserId - String object of the user_id created using Firebase Authentication.
 * @param {String} field - The attribute within Firestore that needs to be modified. This could include username/Mobile SSIDs etc. 
 * @param {String} info - The element to which the field needs to be set. For example, the username would be set to a new string. 
*/
async function updateField(userId, field, info) {
  let user = await UsersRef.doc(userId)
    .update({
      [field]: info,
    })
    .catch((error) => {
      console.error(error);
      throw error;
    });
  return user.writeTime.toDate();
}

/** 
  Adds another organizationId to store in the user document.
 * @param {String} userId - String object of the user_id created using Firebase Authentication.
 * @param {String} organizationId - org id
*/
async function addOrganizationToUser(userId, organizationId, serviceUserId) {
  //add org id
  await UsersRef.doc(userId).collection("organizations").doc(organizationId).set({serviceUserId: serviceUserId});

}

module.exports.update = {
  updatePhoneNumber,
  //  setFCMToken,
  updateField,
  addOrganizationToUser
};

// ----------------------------------------------Delete----------------------------------------------------- //
/** 
 * @returns {FirebaseFirestore.Timestamp.toDate()}
  Returns a timestamp indicating the date of change if deleting the user was successful. 
  Throws an error if a runtime error occured during execution. 
 * @param {String} userId - String object of the user_id created using Firebase Authentication.
*/
async function DeleteUserFromUID(userId) {
  const DevicesRef = await UsersRef.doc(userId).collection("devices");

  DevicesRef.get()
    .then((snapshot) => {
      snapshot.forEach((device) => {
        device.ref.delete();
      });
    })
    .catch((error) => {
      console.error(error);
      throw error;
    });

  UsersRef.doc(userId)
    .delete()
    .then((user) => {
      return user.writeTime.toDate();
    })
    .catch((error) => {
      console.error(error);
      throw error;
    });
}

/** 
 * @returns {Promise}
  Returns a promise to delete the user assocated SSIDs. Throws an error if a runtime error occured during execution. 
 * @param {String} userId - String object of the user_id created using Firebase Authentication.
*/
async function DeleteSSIDsFromUID(userId) {
  try {
    await UsersRef.doc(userId).update({
      mobileSSIDs: admin.firestore.FieldValue.delete(),
    });
    await UsersRef.doc(userId).update({
      desktopSSIDs: admin.firestore.FieldValue.delete(),
    });
  } catch (err) {
    console.error(err);
    throw err;
  }
}

/** 
 * @returns {Promise}
 Deletes old hashes that are expired
 * @param {String} userId - String object of the user_id created using Firebase Authentication.
*/
async function deleteOldHashes() {

  const currentTime = new Date();
  const OldHashesRef = await UsersHashRef.where("timestamp", "<", (currentTime.getTime() - 60000)).get()

  if (!OldHashesRef.empty) {
    OldHashesRef.forEach(hash => {
      UsersHashRef.doc(hash.id).delete()
    })
  }

}

module.exports.delete = {
  DeleteUserFromUID,
  deleteOldHashes
};
