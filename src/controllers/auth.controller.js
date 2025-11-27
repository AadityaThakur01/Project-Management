import { User } from "../models/user.model.js";
import { ApiResponse } from "../utils/api-response.js";
import { ApiError } from "../utils/api-error.js";
import { asyncHandler } from "../utils/async-handler.js";
import { emailVerificationMailgenContent, sendEmail } from "../utils/mail.js";

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
// const getCurrentUser = asyncHandler(async(req,res) => {})
export { registerUser, login, logout, getCurrentUser, verifyEmail };
