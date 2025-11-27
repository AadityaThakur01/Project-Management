import { Router } from "express";
import {
  changeCurrentPassword,
  forgetPasswordRequest,
  getCurrentUser,
  login,
  logout,
  refreshAccessToken,
  registerUser,
  resendEmailVerification,
  resestPassword,
  verifyEmail,
} from "../controllers/auth.controller.js";
import { validate } from "../middlewares/validator.middleware.js";
import {
  userChangeCurrentPasswrodValidators,
  userForgotPasswordValidators,
  userLoginValidators,
  userResetForgotPasswordValidators,
  userValidationUser,
} from "../validators/index.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";

const router = Router();
// unsercured Routes
router.route("/register").post(userValidationUser(), validate, registerUser);
router.route("/login").post(userLoginValidators(), validate, login);
router.route("/verify-email/:verificationToken").get(verifyEmail);
router.route("/refresh-token").post(refreshAccessToken);
router
  .route("/forgot-password")
  .post(userForgotPasswordValidators(), validate, forgetPasswordRequest);
router
  .route("/reset-password/:resetToken")
  .post(userResetForgotPasswordValidators(), validate, resestPassword);

// secured Routes
router.route("/logout").post(verifyJWT, logout);
router.route("/current-user").post(verifyJWT, getCurrentUser);
router
  .route("/change-password")
  .post(
    verifyJWT,
    userChangeCurrentPasswrodValidators(),
    validate,
    changeCurrentPassword,
  );
router
  .route("/resend-email-verification")
  .post(
    verifyJWT,
    userResetForgotPasswordValidators(),
    validate,
    resendEmailVerification,
  );

export default router;
