import { User } from "../models/user.model.js";
import { ApiResponse } from "../utils/api-response.js";
import { ApiError } from "../utils/api-error.js";
import { asyncHandler } from "../utils/async-handler.js";
import { emailVerificationMailgenContent, sendEmail } from "../utils/mail.js";
import jwt from "jsonwebtoken";

const generateAccessAndRefreshToken = async (userId) => {
  try {
    const user = await User.findById(userId);
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });
    return { refreshToken, accessToken };
  } catch (error) {
    throw new ApiError(
      500,
      "something went wrong while generating access token",
    );
  }
};

const registerUser = asyncHandler(async (req, res) => {
  // asynchandler handels the error and try and catch
  const { username, email, password, role } = req.body; // data coming from frontend assuming by body

  const existedUser = await User.findOne({
    $or: [{ username }, { email }], // finding existedUser from the database
  });

  if (existedUser) {
    throw new ApiError(402, "User with email or username already exists", []); // found the existing user and throw the apierror
  }

  const user = await User.create({
    // creating new user if not found in the existing
    email,
    username,
    password,
    isEmailVerified: false,
  });
  const { hashedToken, unHashedToken, tokenExpiry } =
    user.generateTemporaryToken();

  user.emailVerificationToken = hashedToken;
  user.emailVerificationExpiry = tokenExpiry;

  await user.save({ validateBeforeSave: false });

  await sendEmail({
    email: user?.email,
    subject: "Please verify your email",
    mailgenContent: emailVerificationMailgenContent(
      user.username,
      `${req.protocol}://${req.get("host")}/api/v/users/verify-email/${unHashedToken}`,
    ),
  });
  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken -emailVerificationToken -emailVerificationExpiry",
  );
  if (!createdUser) {
    throw new ApiError(500, "Something went wrong while registering the user");
  }

  return res.status(
    200,
    { user: createdUser },
    "User registered succesfully and verificatioin email has been sent on your email",
  );
});

const login = asyncHandler(async (req, res) => {
  const { username, password, email } = req.body;

  if (!email) {
    throw new ApiError(400, "Email is required");
  }

  const user = await User.findOne({ email });

  if (!user) {
    throw new ApiError(400, "User does not existed");
  }

  const isPasswordVerified = await user.isPasswordCorrect(password);

  if (!isPasswordVerified) {
    throw new ApiError(400, "Invalid Credentials");
  }

  // Pass user._id to generateAccessAndRefreshToken
  const { refreshToken, accessToken } = await generateAccessAndRefreshToken(
    user._id,
  );

  const loggedInUser = await User.findById(user._id).select(
    "-password -refreshToken -emailVerificationToken -emailVerificationExpiry",
  );

  const options = {
    httpOnly: true,
    secure: true,
  };

  return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new ApiResponse(
        200,
        {
          user: loggedInUser,
          accessToken,
          refreshToken,
        },
        "User logged in successfully",
      ),
    );
});

const logout = asyncHandler(async (req, res) => {
  await User.findByIdAndUpdate(
    req.user._id,
    {
      $set: {
        refreshToken: "",
      },
    },
    {
      new: true,
    },
  );
  const options = {
    httpOnly: true,
    secure: true,
  };
  return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged Out"));
});
const getCurrentUser = asyncHandler(async (req, res) => {
  return res
    .status(200)
    .json(new ApiResponse(200, req.user, "Current User fetched Successfully"));
});

const verifyEmail = asyncHandler(async (req, res) => {
  const { verificationToken } = req.params; // taking data from the url itself

  if (!verificationToken) {
    // checking for the verficationToken if doesn't exists then throw error
    throw new ApiError(400, "Email verification token is missing");
  }

  let hashedToken = crypto // hashing the verificationtoken
    .createHash("sha256")
    .update(verificationToken)
    .digest("hex");

  const user = await User.findOne({
    emailVerificationToken: hashedToken, // hashing the emailVerificationToken
    emailVerificationExpiry: { $gt: Date.now() }, // email doesn't expiry if it is greater than the date
  });

  if (!user) {
    throw new ApiError(400, "Token is Invalid or Expired");
  }
  user.emailVerificationToken = undefined; // undefined so that it does not contain the unnneccesary data
  user.emailVerificationExpiry = undefined; // undefined so that it does not contain the unnneccesary data

  user.isEmailVerified = true;
  await user.save({ validateBeforeSave: false });

  return res.status(200).json(
    new ApiResponse(
      200,
      {
        isEmailVerified: true,
      },
      "Email is verified",
    ),
  );
});
const resendEmailVerification = asyncHandler(async (req, res) => {
  const user = await User.findById(req.user._id);

  if (!user) {
    throw new ApiError(404, "User doesnt exists");
  }
  if (user.isEmailVerified) {
    throw new ApiError(409, "Email is already Verified");
  }

  const { hashedToken, unHashedToken, tokenExpiry } =
    user.generateTemporaryToken(); // generating hashedToken, unHashedToken, tokenExpiry

  user.emailVerificationToken = hashedToken; // adding to the database
  user.emailVerificationExpiry = tokenExpiry;

  await user.save({ validateBeforeSave: false }); // saving the things in the database

  await sendEmail({
    email: user?.email,
    subject: "Please verify your email",
    mailgenContent: emailVerificationMailgenContent(
      user.username,
      `${req.protocol}://${req.get("host")}/api/v/users/verify-email/${unHashedToken}`,
    ),
  });

  return res
    .status(200)
    .json(new ApiResponse(200, {}, "Mail has been sent to your email ID"));
});
const refreshAccessToken = asyncHandler(async (req, res) => {
  const incomingRefreshToken =
    req.cookies.refreshToken || req.body.refreshToken; // takes the refreshToken from cookies or from body

  if (!incomingRefreshToken) {
    throw new ApiError(401, "Unauthorized Access"); // checking for the refreshtoken is there or not
  }

  try {
    const decodeToken = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET,
    ); // trying to decode the refreshtoken
    const user = await User.findById(decodeToken?._id);

    if (!user) {
      throw new ApiError(401, "Invalid Refresh Token");
    }

    if (incomingRefreshToken !== user?.refreshToken)
      // checking the incomingRefreshToken is same as in the user's refreshToken
      throw new ApiError(401, "Refresh Token is Expired"); // it also be in the database

    const options = {
      httpOnly: true,
      secure: true,
    };

    const { accessToken, refreshToken: newRefreshToken } =
      await generateAccessAndRefreshToken(user._id);

    user.refreshToken = newRefreshToken; // saving the new refreshToken in the database
    await user.save();

    return res
      .status(200)
      .cookie("accessToken", accessToken, options) // creating cookies
      .cookie("refreshToken", refreshToken, options)
      .json(
        new ApiResponse(
          200,
          { accessToken, refreshToken: newRefreshToken },
          "Access Token Refreshed",
        ),
      );
  } catch (error) {
    throw new ApiError(401, "Invalid Refresh Token");
  }
});
// const getCurrentUser = asyncHandler(async(req,res) => {})
export {
  registerUser,
  login,
  logout,
  getCurrentUser,
  verifyEmail,
  resendEmailVerification,
  refreshAccessToken,
};
