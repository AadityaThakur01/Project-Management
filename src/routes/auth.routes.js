import { Router } from "express";
import { login, logout, registerUser } from "../controllers/auth.controller.js";
import { validate } from "../middlewares/validator.middleware.js";
import {
  userLoginValidators,
  userValidationUser,
} from "../validators/index.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";

const router = Router();

router.route("/register").post(userValidationUser(), validate, registerUser);
router.route("/login").post(userLoginValidators(), validate, login);
router.route("/logout").post(verifyJWT, logout);

export default router;
