import { User } from "../models/user.model.js";
import { asyncHandler } from "../utils/async-handler.js";
import { ApiError } from "../utils/api-error.js";
import jwt from "jsonwebtoken";

export const verifyJWT = asyncHandler(async (req, res, next) => {
  const token = // validate if the accessToken is present or not
    req.cookies?.accessToken || // Grabbing the token through cookied
    req.header("Authorization")?.replace("Bearer ", ""); // also from header as mobile does not have cookies and replacing the token because i just
  // need the access token not the bearer and this is encoded token

  if (!token) {
    throw new ApiError(401, "Unauthorized request"); // throwing an error if there is no token
  }
  try {
    const decodeToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET); // decoding the token from jwt as jwt decodes toking throught the access token secret
    const user = await User.findById(decodeToken._id).select(
      // extracting details from user and removing the unneccesary information from the user data
      "-password -refreshToken -emailVerificationToken -emailVerificationExpiry",
    );

    if (!user) {
      throw new ApiError(401, "invalid access token"); // checking if the user exists or not
    }
    req.user = user; // adding the information into the req.user
    next(); // passing to the next middleware if any available next or passing to controllers
  } catch (error) {
    throw new ApiError(401, "Invalid accedd Token"); // catching the error if there is no access token
  }
});
